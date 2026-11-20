#!/usr/bin/env python3
"""Stage 10D IPv6 runtime deny test: actual routed TCP probes and nft counters."""
import json, os, re, socket, subprocess, sys, time
from datetime import datetime, timezone

ZONES={"edge":1,"api":2,"control":3,"admin":4,"monitor":5,"vpn":6,"db":7,"ci":8,"rogue":9,"vpn_peer":10}
TARGETS=("api","control")
RESULTS=[]
TEMP=os.environ.get("RUNNER_TEMP","/tmp")

def cmd(args, timeout=5, capture=True):
    return subprocess.run(args,timeout=timeout,check=False,text=True,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture else subprocess.DEVNULL)

def v6(zone, host=2):
    return f"fd10:10:{ZONES[zone]}::{host}"

def start_listener(zone, port):
    addr=v6(zone)
    server_code=f"""import socket,time
s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('{addr}',{port}))
s.listen(4)
s.settimeout(.5)
end=time.time()+40
while time.time()<end:
    try:
        c,a=s.accept()
        c.sendall(b'OK')
        c.close()
    except socket.timeout:
        pass
s.close()
"""
    ready=False
    proc=subprocess.Popen(["ip","netns","exec",f"rma10d-{zone}","python3","-c",server_code],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    for _ in range(40):
        if proc.poll() is not None: break
        try:
            readiness_code=f"import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); s.settimeout(0.3); s.connect(('{addr}',{port})); s.recv(2); s.close()"
            ready_probe=cmd(["ip","netns","exec",f"rma10d-{zone}","python3","-c",readiness_code],timeout=2)
            if ready_probe.returncode==0: ready=True; break
            time.sleep(0.1)
        except OSError: time.sleep(0.1)
    if not ready:
        if proc.poll() is not None:
            out,err=proc.communicate(timeout=1)
            raise RuntimeError(f"IPv6 listener process exited for {zone}:{port}; stdout={out!r}; stderr={err!r}")
        proc.terminate()
        try: proc.wait(timeout=2)
        except subprocess.TimeoutExpired: proc.kill()
        raise RuntimeError(f"IPv6 listener readiness failed for {zone}:{port}")
    return proc

def drop_counter(zone):
    iface=f"z{ZONES[zone]}r"
    r=cmd(["ip","netns","exec","rma10d-router","nft","list","chain","inet","rma10d","forward"])
    if r.returncode: return None
    for line in r.stdout.splitlines():
        if f'iifname "{iface}"' in line and "meta nfproto ipv6" in line and " drop" in line:
            m=re.search(r"counter packets (\d+) bytes (\d+)",line)
            if m: return int(m.group(1))
    return None

def probe(src,dst,port,spoof=False):
    source=v6(src, 99 if spoof else 2)
    dest=v6(dst)
    code=("import socket\ns=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)\ns.settimeout(1.2)\n"
        f"s.bind(('{source}',0))\ntry:\n    s.connect(('{dest}',{port}))\n    d=s.recv(2)\n    s.close()\n    exit(0 if d==b'OK' else 2)\nexcept OSError:\n    s.close()\n    exit(1)")
    r=cmd(["ip","netns","exec",f"rma10d-{src}","python3","-c",code],timeout=3)
    if r.returncode==0: return True
    if r.returncode!=0 and "Traceback" in (r.stderr or ""): return None
    return False

def record(src,dst,port,expected,actual,delta,label):
    outcome="PASS" if actual is False and delta is not None and delta>0 else ("FAIL" if actual is True else "INCONCLUSIVE")
    RESULTS.append({"test":f"IPv6 {src}->{dst}:{port}","expected":expected,"actual":"ALLOW" if actual else ("DENY" if actual is False else "UNKNOWN"),"counter_delta":delta,"outcome":outcome,"description":label})
    print(f"{outcome}: IPv6 {src}->{dst}:{port}; actual={'ALLOW' if actual else ('DENY' if actual is False else 'UNKNOWN')}; nft drop delta={delta}; {label}")

def main():
    listeners={}
    try:
        for dst in TARGETS:
            port=19400+ZONES[dst]
            listeners[dst]=start_listener(dst,port)
        # Every zone ingress is exercised to both target zones (except local, non-forwarded tests).
        for src in ZONES:
            for dst in TARGETS:
                if src==dst: continue
                port=19400+ZONES[dst]
                before=drop_counter(src)
                actual=probe(src,dst,port)
                after=drop_counter(src)
                delta=None if before is None or after is None else after-before
                record(src,dst,port,"DENY",actual,delta,"IPv6 forwarded traffic must be dropped on zone ingress before established-state acceptance")
        # Attempt source-address spoofing over IPv6 too; ingress policy is protocol-family-wide.
        for src,dst in (("edge","api"),("vpn_peer","control")):
            port=19400+ZONES[dst]
            alias=v6(src,99)
            iface=f"z{ZONES[src]}c"
            setup=cmd(["ip","-n",f"rma10d-{src}","-6","addr","add",alias+"/64","dev",iface,"nodad"])
            if setup.returncode:
                RESULTS.append({"test":f"IPv6 spoof {src}->{dst}","expected":"deny","actual":"UNKNOWN","outcome":"INCONCLUSIVE","passed":False,"reason":setup.stderr})
                print(f"INCONCLUSIVE: IPv6 spoof alias setup failed for {src}: {setup.stderr.strip()}")
                continue
            try:
                before=drop_counter(src)
                actual=probe(src,dst,port,spoof=True)
                after=drop_counter(src)
                delta=None if before is None or after is None else after-before
                record(src,dst,port,"DENY",actual,delta,"IPv6 alternate source address must not bypass ingress IPv6 drop")
            finally:
                cmd(["ip","-n",f"rma10d-{src}","-6","addr","del",alias+"/64","dev",iface])
        payload={"stage":"10D-IPv6-runtime","generated_at":datetime.now(timezone.utc).isoformat(),"checks":RESULTS,
            "passed":sum(x["outcome"]=="PASS" for x in RESULTS),"failed":sum(x["outcome"]=="FAIL" for x in RESULTS),
            "inconclusive":sum(x["outcome"]=="INCONCLUSIVE" for x in RESULTS),
            "scope":"Disposable CI namespaces only; no host firewall or production network changes."}
        path=os.path.join(TEMP,"phase-a-stage10d-ipv6-runtime-evidence.json")
        with open(path,"w",encoding="utf-8") as f: json.dump(payload,f,indent=2)
        print(f"IPv6 Runtime Summary: PASS={payload['passed']} FAIL={payload['failed']} INCONCLUSIVE={payload['inconclusive']}; evidence={path}")
        if payload["failed"] or payload["inconclusive"]: raise SystemExit(1)
    finally:
        for proc in listeners.values():
            if proc.poll() is None: proc.terminate()
        for proc in listeners.values():
            try: proc.wait(timeout=2)
            except subprocess.TimeoutExpired: proc.kill()

if __name__=="__main__": main()
