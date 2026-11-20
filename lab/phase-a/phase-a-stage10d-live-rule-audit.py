#!/usr/bin/env python3
"""Stage 10D live nftables rule-order and allow-list audit in disposable lab."""
import json, os, re, subprocess
from datetime import datetime, timezone

ZONES={"edge":1,"api":2,"control":3,"admin":4,"monitor":5,"vpn":6,"db":7,"ci":8,"rogue":9,"vpn_peer":10}
EXPECTED_ALLOW={
("10.20.1.2","10.20.2.2",8080),
("10.20.2.2","10.20.3.2",8443),
("10.20.3.2","10.20.7.2",5432),
("10.20.3.2","10.20.6.2",9445),
("10.20.4.2","10.20.3.2",9443),
("10.20.4.2","10.20.3.2",9444),
("10.20.5.2","10.20.2.2",9100),
("10.20.5.2","10.20.3.2",9100),
}
checks=[]
def check(name,passed,details):
 outcome="PASS" if passed else "FAIL"
 checks.append({"check":name,"outcome":outcome,"passed":passed,"details":details})
 print(f"{outcome}: {name} — {details}")
def run():
 r=subprocess.run(["ip","netns","exec","rma10d-router","nft","list","chain","inet","rma10d","forward"],capture_output=True,text=True,timeout=5)
 if r.returncode: raise SystemExit(f"nft chain retrieval failed: {r.stderr}")
 lines=[ln.strip() for ln in r.stdout.splitlines() if ln.strip() and not ln.strip().startswith("chain ")]
 # Identify ordered guard/accept/drop rules from live chain output.
 established=[i for i,l in enumerate(lines) if "ct state established,related" in l]
 check("single established-state accept",len(established)==1, f"found {len(established)} rule(s)")
 eidx=established[0] if established else -1
 set_result=subprocess.run(["ip","netns","exec","rma10d-router","nft","list","set","inet","rma10d","revoked_tcp_flows"],capture_output=True,text=True,timeout=5,check=False)
 set_ok=set_result.returncode==0 and re.search(r"type ipv4_addr \. ipv4_addr \. inet_service",set_result.stdout) is not None
 check("dynamic TCP revocation set exists with exact 3-tuple key",set_ok,
       set_result.stdout.strip() if set_result.returncode==0 else set_result.stderr.strip())
 peer_set=subprocess.run(["ip","netns","exec","rma10d-router","nft","list","set","inet","rma10d","revoked_peer_sources"],capture_output=True,text=True,timeout=5,check=False)
 peer_set_ok=peer_set.returncode==0 and re.search(r"type ipv4_addr",peer_set.stdout) is not None
 check("dynamic peer-source revocation set exists with IPv4 key",peer_set_ok,
       peer_set.stdout.strip() if peer_set.returncode==0 else peer_set.stderr.strip())
 peer_revoke_indices=[i for i,l in enumerate(lines) if 'comment "stage10d-peer-source-revocation"' in l]
 check("single peer-source revocation guard precedes established accept",
       len(peer_revoke_indices)==1 and eidx>=0 and peer_revoke_indices[0]<eidx,
       f"peer-source indices={peer_revoke_indices}; established index={eidx}")
 revoke_indices=[i for i,l in enumerate(lines) if 'comment "stage10d-revocation-set"' in l]
 check("single dynamic revocation guard precedes established accept",
       len(revoke_indices)==1 and eidx>=0 and revoke_indices[0]<eidx,
       f"revocation indices={revoke_indices}; established index={eidx}")
 anti=[]; v6drops=[]
 for z,i in ZONES.items():
  iface=f"z{i}r"; assigned=f"10.20.{i}.2"
  anti.append(any(f'iifname "{iface}"' in l and f"ip saddr != {assigned}" in l and " drop" in l for l in lines))
  v6drops.append(any(f'iifname "{iface}"' in l and "meta nfproto ipv6" in l and " drop" in l for l in lines))
 check("IPv4 source anti-spoof guard on all 10 ingress interfaces",all(anti),f"{sum(anti)}/10 present")
 check("IPv6 ingress drop guard on all 10 interfaces",all(v6drops),f"{sum(v6drops)}/10 present")
 guard_indices=[]
 for l in lines:
  if "iifname" in l and ("ip saddr !=" in l or "meta nfproto ipv6" in l) and " drop" in l:
   guard_indices.append(lines.index(l))
 check("anti-spoof and IPv6 guards precede established accept",bool(guard_indices) and eidx>=0 and max(guard_indices)<eidx,
       f"last guard index={max(guard_indices) if guard_indices else None}, established index={eidx}")
 accepts=[l for l in lines if l.rstrip().endswith(" accept")]
 check("no extra accept rules outside established plus explicit allow-list",len(accepts)==9,f"{len(accepts)} accept rules total; expected 9")
 actual_allow=set()
 for l in accepts:
  if "ct state established,related" in l: continue
  m=re.search(r"ip saddr (\S+) ip daddr (\S+) tcp dport (\d+)",l)
  if m: actual_allow.add((m.group(1),m.group(2),int(m.group(3))))
 check("explicit TCP allow-list matches approved tuples exactly",actual_allow==EXPECTED_ALLOW,
       f"observed {len(actual_allow)} tuples; missing={sorted(EXPECTED_ALLOW-actual_allow)}; unexpected={sorted(actual_allow-EXPECTED_ALLOW)}")
 drops=set()
 for l in lines:
  m=re.search(r"ip saddr (\S+) ip daddr (\S+) tcp dport (\d+) counter .* drop$",l)
  if m:drops.add((m.group(1),m.group(2),int(m.group(3))))
 overlap=drops & actual_allow
 check("explicit deny rules do not overlap approved allow tuples",not overlap,f"overlap={sorted(overlap)}")
 # A broad accept is forbidden; only exact state and whitelisted tuple accepts are acceptable.
 unexpected=[l for l in accepts if "ct state established,related" not in l and not re.search(r"ip saddr \S+ ip daddr \S+ tcp dport \d+ .* accept$",l)]
 check("no wildcard or non-TCP accept rule",not unexpected,f"unexpected={unexpected}")
 payload={"stage":"10D-live-rule-audit","generated_at":datetime.now(timezone.utc).isoformat(),"checks":checks,
          "passed":sum(c["passed"] for c in checks),"failed":sum(not c["passed"] for c in checks),
          "scope":"Live nftables rules inside disposable CI router namespace; no production evidence."}
 path=os.path.join(os.environ.get("RUNNER_TEMP","/tmp"),"phase-a-stage10d-rule-audit-evidence.json")
 with open(path,"w",encoding="utf-8") as f:json.dump(payload,f,indent=2)
 print(f"Rule audit summary: PASS={payload['passed']} FAIL={payload['failed']} evidence={path}")
 if payload["failed"]: raise SystemExit(1)
if __name__=="__main__":run()
