#!/usr/bin/env python3
"""Stage 10D route matrix tests in disposable rma10d namespaces."""
import json, os, socket, subprocess, time
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
 return subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout,check=False)
def start_server(dst,port):
 code=("import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
       f"s.bind(('0.0.0.0',{port})); s.listen(8); s.settimeout(.5); end=time.time()+25;\n"
       "while time.time()<end:\n try: c,a=s.accept(); c.sendall(b'OK'); c.close()\n except socket.timeout: pass\ns.close()")
 return subprocess.Popen(["ip","netns","exec","rma10d-"+dst,"python3","-c",code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def probe(src,dst,port):
 ip=f"10.20.{ZONES[dst]}.2"
 code=f"import socket; s=socket.socket(); s.settimeout(1); s.connect(('{ip}',{port})); d=s.recv(2); s.close(); exit(0 if d==b'OK' else 2)"
 return run(["ip","netns","exec","rma10d-"+src,"python3","-c",code]).returncode==0
def counter_value(src,dst,port,action):
 source=f"10.20.{ZONES[src]}.2"; target=f"10.20.{ZONES[dst]}.2"
 try:
  result=subprocess.run(["ip","netns","exec","rma10d-router","nft","list","chain","inet","rma10d","forward"],capture_output=True,text=True,timeout=4,check=False)
 except (subprocess.TimeoutExpired,OSError): return None
 if result.returncode!=0: return None
 import re
 for line in result.stdout.splitlines():
  if source in line and target in line and f"tcp dport {port}" in line and line.rstrip().endswith(action):
   match=re.search(r"counter packets (\d+) bytes (\d+)",line)
   if match: return int(match.group(1))
 return None
def record(src,dst,port,expect,description,actual,counter_delta):
 outcome="FAIL" if actual!=expect else ("PASS" if counter_delta is not None and counter_delta>0 else "INCONCLUSIVE")
 passed=outcome=="PASS"
 RESULTS.append({"test":f"{src}->{dst}:{port}","expected":"ALLOW" if expect else "DENY","actual":"ALLOW" if actual else "DENY","outcome":outcome,"passed":passed,"counter_delta":counter_delta,"description":description})
 print(f"{outcome} {src}->{dst}:{port} expected={'ALLOW' if expect else 'DENY'} actual={'ALLOW' if actual else 'DENY'} counter_delta={counter_delta} — {description}")
def record_inconclusive(src,dst,port,expect,description,reason):
 RESULTS.append({"test":f"{src}->{dst}:{port}","expected":"ALLOW" if expect else "DENY","actual":"UNKNOWN","outcome":"INCONCLUSIVE","passed":False,"description":description,"reason":reason})
 print(f"INCONCLUSIVE {src}->{dst}:{port} expected={'ALLOW' if expect else 'DENY'} actual=UNKNOWN — {description} ({reason})")
def main():
 servers={}
 readiness={}
 try:
  for src,dst,port,expect,desc in MATRIX:
   key=(dst,port)
   if key not in servers:
    servers[key]=start_server(dst,port)
    ready=False
    for _ in range(20):
     if servers[key].poll() is not None: break
     try:
      if probe(dst,dst,port): ready=True; break
     except Exception: pass
     time.sleep(.1)
    readiness[key]=ready
    if not ready:
     record_inconclusive(src,dst,port,expect,desc,"destination listener/readiness probe failed; policy path not evaluated"); continue
   if readiness.get(key) is False:
    record_inconclusive(src,dst,port,expect,desc,"destination readiness previously failed for this dst/port"); continue
   before=counter_value(src,dst,port,"accept" if expect else "drop")
   try: actual=probe(src,dst,port)
   except Exception: actual=None
   after=counter_value(src,dst,port,"accept" if expect else "drop")
   delta=None if before is None or after is None else after-before
   if actual is None:
    record_inconclusive(src,dst,port,expect,desc,"probe execution error")
   elif actual!=expect:
    record(src,dst,port,expect,desc,actual,delta)
   elif delta is None:
    record_inconclusive(src,dst,port,expect,desc,"matching nftables counter unavailable")
   elif delta<=0:
    record_inconclusive(src,dst,port,expect,desc,"socket result lacks matching nftables counter increment")
   else: record(src,dst,port,expect,desc,actual,delta)
  payload={"stage":"10D-route-matrix","generated_at":datetime.now(timezone.utc).isoformat(),"checks":RESULTS,"passed":sum(x["outcome"]=="PASS" for x in RESULTS),"failed":sum(x["outcome"]=="FAIL" for x in RESULTS),"inconclusive":sum(x["outcome"]=="INCONCLUSIVE" for x in RESULTS),"scope":"Disposable CI namespaces only; not production/cloud proof."}
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
