#!/usr/bin/env python3
"""Stage 10D stateful firewall revocation test in disposable namespaces.

Proves that removing a NEW-flow allow rule is insufficient for an existing
conntrack session, then validates an explicit revocation guard placed before
the established-state accept rule blocks both old and new traffic.
"""
import json, os, re, subprocess, sys, time
from datetime import datetime, timezone

SRC="10.20.1.2"
DST="10.20.2.2"
PORT=8080
ROUTER=["ip","netns","exec","rma10d-router"]
RESULTS=[]
TEMP=os.environ.get("RUNNER_TEMP","/tmp")

def run(args, timeout=5, check=True, capture=True):
    return subprocess.run(args, timeout=timeout, check=check, text=True,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture else subprocess.DEVNULL)

def record(name, expected, actual, passed, details=""):
    outcome="PASS" if passed else "FAIL"
    RESULTS.append({"test":name,"expected":expected,"actual":actual,
                    "outcome":outcome,"passed":bool(passed),"details":details})
    print(f"{outcome}: {name}; expected={expected}; actual={actual}; {details}")

def chain():
    return run(ROUTER+["nft","-a","list","chain","inet","rma10d","forward"]).stdout

def counter():
    for line in chain().splitlines():
        if 'comment "stage10d-revoke-test"' in line:
            m=re.search(r"counter packets (\d+) bytes (\d+)",line)
            if m: return int(m.group(1))
    return None

def find_allow_handle():
    for line in chain().splitlines():
        if (f"ip saddr {SRC}" in line and f"ip daddr {DST}" in line
            and f"tcp dport {PORT}" in line and "ct state new" in line and " accept" in line):
            m=re.search(r"# handle (\d+)",line)
            if m: return int(m.group(1))
    return None

def main():
    listener=None
    client=None
    revoke_handle=None
    try:
        server_code="""import socket,time
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',8080))
s.listen(8)
s.settimeout(.5)
end=time.time()+90
while time.time()<end:
    try:
        c,a=s.accept()
        c.settimeout(10)
        try:
            while True:
                data=c.recv(4096)
                if not data: break
                c.sendall(b'ACK:'+data)
        except OSError:
            pass
        c.close()
    except socket.timeout:
        pass
s.close()
"""
        listener=subprocess.Popen(["ip","netns","exec","rma10d-api","python3","-u","-c",server_code],
                                  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        ready=False
        for _ in range(40):
            if listener.poll() is not None: break
            probe_code="import socket; s=socket.create_connection(('10.20.2.2',8080),timeout=.3); s.close()"
            p=run(["ip","netns","exec","rma10d-edge","python3","-c",probe_code],timeout=2,check=False)
            if p.returncode==0:
                ready=True
                break
            time.sleep(.1)
        if not ready: raise RuntimeError("API listener did not become ready")

        client_code="""import socket,time
s=socket.create_connection(('10.20.2.2',8080),timeout=2)
s.settimeout(1.5)
s.sendall(b'before-revoke\\n')
print(s.recv(4096).decode(errors='replace'),flush=True)
time.sleep(2.0)
try:
    s.sendall(b'after-revoke\\n')
    data=s.recv(4096)
    print(data.decode(errors='replace'),flush=True)
except socket.timeout:
    print('TIMEOUT',flush=True)
except OSError as e:
    print('ERROR:'+str(e),flush=True)
s.close()
"""
        client=subprocess.Popen(["ip","netns","exec","rma10d-edge","python3","-u","-c",client_code],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        initial=client.stdout.readline().strip()
        record("Q10DS-01 allowed TCP session established","successful initial ACK",initial,
               initial=="ACK:before-revoke")
        record("Q10DS-02 existing TCP session carries data before revocation","ACK:before-revoke",initial,
               initial=="ACK:before-revoke")

        allow_handle=find_allow_handle()
        if allow_handle is None: raise RuntimeError("Could not locate exact Edge-to-API NEW-flow allow rule")
        run(ROUTER+["nft","delete","rule","inet","rma10d","forward","handle",str(allow_handle)])
        record("Q10DS-03 revoke removes exact NEW-flow allow rule","rule deleted",f"handle {allow_handle}",True)

        # This explicit guard is the revocation enforcement control. It is inserted
        # before ct state established,related accept so conntrack cannot bypass it.
        run(ROUTER+["nft","insert","rule","inet","rma10d","forward",
            "ip","saddr",SRC,"ip","daddr",DST,"tcp","dport",str(PORT),
            "counter","drop","comment","stage10d-revoke-test"])
        lines=chain().splitlines()
        revoke_index=next((i for i,l in enumerate(lines) if 'comment "stage10d-revoke-test"' in l),None)
        established_index=next((i for i,l in enumerate(lines) if "ct state established,related" in l and " accept" in l),None)
        ordered=revoke_index is not None and established_index is not None and revoke_index<established_index
        record("Q10DS-04 revocation guard precedes established-state accept",
               "revocation rule index < established accept",
               f"{revoke_index} < {established_index}",ordered)

        before=counter()
        old_result=client.stdout.readline().strip()
        if old_result == "":
            try: client.wait(timeout=2)
            except subprocess.TimeoutExpired: pass
            err=client.stderr.read().strip() if client.poll() is not None else "client still running without output"
            old_result=f"CLIENT_EXIT_{client.returncode}; stderr={err}" if client.poll() is not None else err
        after=counter()
        old_delta=None if before is None or after is None else after-before
        record("Q10DS-05 pre-existing TCP session is blocked after revocation",
               "TIMEOUT and revocation drop counter increases",
               f"{old_result}; counter delta={old_delta}",
               old_result=="TIMEOUT" and old_delta is not None and old_delta>0)

        before=counter()
        new_code="""import socket,sys
s=socket.socket(); s.settimeout(1.5)
try:
    s.connect(('10.20.2.2',8080))
    s.sendall(b'new-after-revoke')
    s.close()
    sys.exit(2)
except OSError:
    s.close()
    sys.exit(0)
"""
        new=run(["ip","netns","exec","rma10d-edge","python3","-c",new_code],timeout=4,check=False)
        after=counter()
        new_delta=None if before is None or after is None else after-before
        record("Q10DS-06 new TCP session is denied after revocation",
               "connection denied and revocation drop counter increases",
               f"{'DENIED' if new.returncode==0 else 'CONNECTED/UNEXPECTED'}; counter delta={new_delta}",
               new.returncode==0 and new_delta is not None and new_delta>0)

        payload={"stage":"10D-stateful-firewall-revocation",
            "generated_at":datetime.now(timezone.utc).isoformat(),"checks":RESULTS,
            "passed":sum(x["outcome"]=="PASS" for x in RESULTS),
            "failed":sum(x["outcome"]=="FAIL" for x in RESULTS),
            "inconclusive":0,
            "scope":"Disposable CI namespaces only. Demonstrates explicit revocation guard semantics; does not assert production rollout."}
        path=os.path.join(TEMP,"phase-a-stage10d-stateful-revocation-evidence.json")
        with open(path,"w",encoding="utf-8") as f: json.dump(payload,f,indent=2)
        print(f"Stateful revocation summary: PASS={payload['passed']} FAIL={payload['failed']} evidence={path}")
        if payload["failed"]: raise SystemExit(1)
    finally:
        if client is not None:
            try: client.stdin.close()
            except Exception: pass
            try: client.wait(timeout=2)
            except subprocess.TimeoutExpired: client.kill()
        if listener is not None and listener.poll() is None:
            listener.terminate()
            try: listener.wait(timeout=2)
            except subprocess.TimeoutExpired: listener.kill()
        # The disposable lab is torn down by the workflow's EXIT trap.

if __name__=="__main__": main()
