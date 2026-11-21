#!/usr/bin/env python3
"""Stage 10D route matrix. DENY requires a positive destination control and kernel drop-counter evidence."""
import json, os, re, socket, subprocess, time
from datetime import datetime, timezone
ZONES={"edge":1,"api":2,"control":3,"admin":4,"monitor":5,"vpn":6,"db":7,"ci":8,"rogue":9,"vpn_peer":10}
MATRIX=[
("edge","api",8080,True,"Edge to user API"),
("api","control",8443,True,"User API to control API"),
("control","db",5432,True,"Control to DB"),
("control","vpn",9445,True,"Control to VPN management"),
("admin","control",9443,True,"Admin to control endpoint 1"),
("admin","control",9444,True,"Admin to control endpoint 2"),
("monitor","api",9100,True,"Monitor to API health"),
("monitor","control",9100,True,"Monitor to control health"),
("edge","control",8443,False,"Edge cannot bypass API"),
("api","db",5432,False,"API cannot directly access DB"),
("api","admin",9443,False,"API cannot reach Admin zone"),
("monitor","control",8443,False,"Monitor cannot access control API"),
("vpn","db",5432,False,"VPN cannot directly access DB"),
("vpn","ci",8080,False,"VPN cannot reach CI"),
("admin","db",5432,False,"Admin cannot directly access DB"),
("rogue","api",8080,False,"Rogue cannot reach API"),
("vpn_peer","control",8443,False,"VPN peer cannot reach control API")]
RESULTS=[]
TEMP=os.environ.get("RUNNER_TEMP","/tmp")
def run(args,timeout=4):
 try: return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False,text=True)
 except subprocess.TimeoutExpired as exc: return exc
def start_server(dst,port):
 code=("import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
       f"s.bind(('0.0.0.0',{port})); s.listen(8); s.settimeout(.5); end=time.time()+40;\n"
       "while time.time()<end:\n try: c,a=s.accept(); c.sendall(b'OK'); c.close()\n"
       " except socket.timeout: pass\n"
       "s.close()")
 return subprocess.Popen(["ip","netns","exec","rma10d-"+dst,"python3","-c",code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def probe(src,dst,port):
 ip=f"10.20.{ZONES[dst]}.2"
 code=f"import socket; s=socket.socket(); s.settimeout(1.5); s.connect(('{ip}',{port})); d=s.recv(2); s.close(); exit(0 if d==b'OK' else 2)"
 result=run(["ip","netns","exec","rma10d-"+src,"python3","-c",code],timeout=3)
 if isinstance(result,subprocess.TimeoutExpired): return None,"probe timed out"
 if result.returncode==0: return True,"connected and received OK"
 return False,(result.stderr or result.stdout or f"exit {result.returncode}").strip()[:300]
def nft_listing():
 r=run(["ip","netns","exec","rma10d-router","nft","-a","list","chain","inet","rma10d","forward"],timeout=3)
 if isinstance(r,subprocess.TimeoutExpired) or r.returncode!=0: return None
 return r.stdout
def find_handle(listing,src_ip,dst_ip,port,action):
 if listing is None: return None
 pattern=rf"ip saddr {re.escape(src_ip)} ip daddr {re.escape(dst_ip)} tcp dport {port} counter packets \\d+ bytes \\d+ {action}.*# handle (\d+)"
 match=re.search(pattern,listing)
 return int(match.group(1)) if match else None
def rule_packets(handle):
 listing=nft_listing()
 if listing is None: return None
 for line in listing.splitlines():
  if re.search(rf"# handle {handle}\b",line):
   m=re.search(r"counter packets (\d+) bytes (\d+)",line)
   return int(m.group(1)) if m else None
 return None
def record(src,dst,port,expect,description,status,actual,detail):
 passed=status=="PASS"
 RESULTS.append({"test":f"{src}->{dst}:{port}","expected":"ALLOW" if expect else "DENY","actual":actual,"status":status,"passed":passed,"description":description,"detail":detail})
 print(f"{status} {src}->{dst}:{port} expected={'ALLOW' if expect else 'DENY'} actual={actual} — {description}; {detail}")
def main():
 servers={}
 try:
  for src,dst,port,expect,desc in MATRIX:
   key=(dst,port)
   if key not in servers:
    servers[key]=start_server(dst,port)
    ready=False; readiness_detail="listener not ready"
    for _ in range(30):
     if servers[key].poll() is not None:
      readiness_detail=f"listener process exited {servers[key].returncode}"; break
     result,detail=probe(dst,dst,port)
     if result is True: ready=True; readiness_detail="destination positive control succeeded"; break
     readiness_detail=detail
     time.sleep(.1)
    if not ready:
     record(src,dst,port,expect,"destination preflight", "INCONCLUSIVE","UNKNOWN",readiness_detail)
     continue
   if expect:
    actual,detail=probe(src,dst,port)
    status="PASS" if actual is True else "FAIL"
    record(src,dst,port,expect,desc,status,"ALLOW" if actual is True else "NO-CONNECTION",detail)
   else:
    src_ip=f"10.20.{ZONES[src]}.2"; dst_ip=f"10.20.{ZONES[dst]}.2"
    # Positive control: install an exact temporary Allow and prove the source can
    # reach the listener through the router before evaluating the denied path.
    add_allow=run(["ip","netns","exec","rma10d-router","nft","insert","rule","inet","rma10d","forward",
                    "ip","saddr",src_ip,"ip","daddr",dst_ip,"tcp","dport",str(port),"counter","accept"])
    listing=nft_listing()
    allow_handle=find_handle(listing,src_ip,dst_ip,port,"accept")
    positive=False; positive_detail="temporary Allow setup failed"
    if add_allow.returncode==0 and allow_handle is not None:
     positive,positive_detail=probe(src,dst,port)
    allow_removed=False
    if allow_handle is not None:
     rem=run(["ip","netns","exec","rma10d-router","nft","delete","rule","inet","rma10d","forward","handle",str(allow_handle)])
     allow_removed=rem.returncode==0
    # Exact temporary drop counter gives per-test packet attribution.
    add_drop=run(["ip","netns","exec","rma10d-router","nft","insert","rule","inet","rma10d","forward",
                   "ip","saddr",src_ip,"ip","daddr",dst_ip,"tcp","dport",str(port),"counter","drop"])
    listing=nft_listing()
    drop_handle=find_handle(listing,src_ip,dst_ip,port,"drop")
    before=rule_packets(drop_handle) if drop_handle is not None else None
    actual,detail=probe(src,dst,port)
    after=rule_packets(drop_handle) if drop_handle is not None else None
    delta=(after-before) if before is not None and after is not None else None
    drop_removed=False
    if drop_handle is not None:
     rem=run(["ip","netns","exec","rma10d-router","nft","delete","rule","inet","rma10d","forward","handle",str(drop_handle)])
     drop_removed=rem.returncode==0
    actual_text="ALLOW" if actual is True else "DENY" if actual is False else "UNKNOWN"
    if add_allow.returncode!=0 or allow_handle is None or not allow_removed or positive is not True or add_drop.returncode!=0 or drop_handle is None or not drop_removed:
     status="INCONCLUSIVE"
    else:
     status="PASS" if actual is False and delta is not None and delta>0 else ("FAIL" if actual is True else "INCONCLUSIVE")
    record(src,dst,port,expect,desc,status,actual_text,
           f"positive_control={positive}; positive_detail={positive_detail}; allow_rule_removed={allow_removed}; deny_probe={detail}; exact_drop_counter_delta={delta}; drop_rule_removed={drop_removed}")
  payload={"stage":"10D-route-matrix","generated_at":datetime.now(timezone.utc).isoformat(),"checks":RESULTS,
           "passed":sum(x["status"]=="PASS" for x in RESULTS),"failed":sum(x["status"]=="FAIL" for x in RESULTS),
           "inconclusive":sum(x["status"]=="INCONCLUSIVE" for x in RESULTS),
           "scope":"Disposable namespaces; DENY requires destination preflight and attributable nftables forward-drop counter increase."}
  path=os.path.join(TEMP,"phase-a-stage10d-route-matrix-evidence.json")
  with open(path,"w",encoding="utf-8") as f: json.dump(payload,f,indent=2)
  print(f"Summary: PASS={payload['passed']} FAIL={payload['failed']} INCONCLUSIVE={payload['inconclusive']}; evidence {path}")
  if payload["failed"] or payload["inconclusive"]: raise SystemExit(1)
 finally:
  for p in servers.values():
   if p.poll() is None: p.terminate()
  for p in servers.values():
   try: p.wait(timeout=2)
   except subprocess.TimeoutExpired: p.kill()
if __name__=="__main__": main()
