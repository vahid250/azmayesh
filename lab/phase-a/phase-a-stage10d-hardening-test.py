#!/usr/bin/env python3
"""Stage 10D hardening tests. Inconclusive environmental probes fail the gate."""
from __future__ import annotations
import datetime, http.client, json, os, pathlib, socket, ssl, subprocess, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

ZONES=("edge","api","control","admin","monitor","vpn","db","ci","rogue","vpn_peer")
RESULTS=[]
POLICY={"available":True}
TLS_EVIDENCE={"server_handshake_rejections":0,"last_rejection":""}
def record(test, expected, actual, status):
    RESULTS.append({"test":test,"expected":expected,"actual":actual,"status":status,"passed":status=="PASS"})
    print(f"{status}: {test}: expected={expected}; actual={actual}")
def openssl(*args):
    subprocess.run(["openssl",*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
def make_cert(d,name,ca_key,ca_crt,uri=None,cn=None,server=False):
    key=d/f"{name}.key"; csr=d/f"{name}.csr"; crt=d/f"{name}.crt"
    openssl("req","-new","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(csr),"-subj",f"/CN={cn or name}")
    ext=d/f"{name}.ext"
    usage="keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n" if server else "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
    if uri and not server: usage += f"subjectAltName=URI:{uri}\n"
    ext.write_text(usage,encoding="utf-8")
    openssl("x509","-req","-in",str(csr),"-CA",str(ca_crt),"-CAkey",str(ca_key),"-CAcreateserial","-out",str(crt),"-days","2","-sha256","-extfile",str(ext))
    return key,crt
def workload_uri(cert):
    uris=[value for kind,value in cert.get("subjectAltName",()) if kind=="URI"]
    return uris[0] if len(uris)==1 else None
class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"healthy")
    def log_message(self,*args): pass
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        cert=self.connection.getpeercert()
        if self.path!="/mutate":
            self.send_response(404); self.end_headers(); return
        if workload_uri(cert)!="spiffe://rma/control":
            self.send_response(403); self.end_headers(); return
        if not POLICY["available"]:
            self.send_response(503); self.end_headers(); return
        self.send_response(200); self.end_headers(); self.wfile.write(b"accepted")
    def log_message(self,*args): pass
class TLSHTTPServer(HTTPServer):
    def __init__(self,address,handler,ctx):
        super().__init__(address,handler); self.ctx=ctx
    def get_request(self):
        raw,addr=super().get_request()
        try:
            tls=self.ctx.wrap_socket(raw,server_side=True,do_handshake_on_connect=False)
            tls.do_handshake()
            return tls,addr
        except (ssl.SSLError,OSError) as exc:
            TLS_EVIDENCE["server_handshake_rejections"]+=1
            TLS_EVIDENCE["last_rejection"]=type(exc).__name__+": "+str(exc)[:240]
            raw.close()
            raise
def request(port,ctx):
    conn=http.client.HTTPSConnection("localhost",port,context=ctx,timeout=2)
    try:
        conn.request("POST","/mutate",body=b"test")
        response=conn.getresponse(); status=response.status; response.read()
        return status
    finally: conn.close()
def context(ca,cert=None,key=None):
    c=ssl.create_default_context(cafile=str(ca))
    if cert and key: c.load_cert_chain(str(cert),str(key))
    return c
def nft_drop_packets():
    result=subprocess.run(["ip","netns","exec","rma10d-router","nft","-a","list","chain","inet","rma10d","forward"],capture_output=True,text=True,timeout=3)
    if result.returncode!=0: return None
    matches=__import__("re").findall(r"counter packets (\d+) bytes (\d+)",result.stdout)
    return int(matches[-1][0]) if matches else None
def egress_probe(namespace,port=8443):
    code=("import socket; s=socket.socket(); s.settimeout(1.5); s.connect(('10.20.11.2',"+str(port)+")); "
          "d=s.recv(2); s.close(); exit(0 if d==b'OK' else 2)")
    try:
        result=subprocess.run(["ip","netns","exec","rma10d-"+namespace,"python3","-c",code],capture_output=True,text=True,timeout=3)
        return result.returncode==0,(result.stderr or result.stdout or f"exit {result.returncode}")[:240]
    except subprocess.TimeoutExpired: return None,"probe timed out"
def health_freshness(age,threshold=30.0):
    if age is None or not isinstance(age,(int,float)) or not threshold>0: return "ERROR"
    if age<0: return "ERROR"
    return "HEALTHY" if age<=threshold else "UNKNOWN/STALE"
def main():
    with tempfile.TemporaryDirectory(prefix="rma10dh-") as td:
        d=pathlib.Path(td)
        ca_key=d/"ca.key"; ca_crt=d/"ca.crt"
        openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(ca_key),"-out",str(ca_crt),"-days","2","-subj","/CN=RMA-Test-CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign")
        control_key,control_crt=make_cert(d,"control",ca_key,ca_crt,"spiffe://rma/control","rma-control")
        # Deliberately spoof CN while SAN URI identifies a different workload.
        user_key,user_crt=make_cert(d,"user-api",ca_key,ca_crt,"spiffe://rma/user-api","rma-control")
        server_key,server_crt=make_cert(d,"localhost",ca_key,ca_crt,server=True)
        rogue_ca_key=d/"rogue-ca.key"; rogue_ca_crt=d/"rogue-ca.crt"
        openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(rogue_ca_key),"-out",str(rogue_ca_crt),"-days","2","-subj","/CN=Untrusted-Test-CA")
        rogue_dir=d/"untrusted"; rogue_dir.mkdir(mode=0o700)
        rogue_key,rogue_crt=make_cert(rogue_dir,"rogue-control",rogue_ca_key,rogue_ca_crt,"spiffe://rma/control","rma-control")
        server_ctx=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_ctx.load_cert_chain(str(server_crt),str(server_key))
        server_ctx.load_verify_locations(cafile=str(ca_crt)); server_ctx.verify_mode=ssl.CERT_REQUIRED
        verify=subprocess.run(["openssl","verify","-purpose","sslclient","-CAfile",str(ca_crt),str(control_crt)],check=False,capture_output=True,text=True)
        record("client cert CA and EKU positive precheck","verify exit 0",f"exit {verify.returncode}", "PASS" if verify.returncode==0 else "FAIL")
        httpd=TLSHTTPServer(("127.0.0.1",0),Handler,server_ctx)
        port=httpd.server_address[1]
        thread=threading.Thread(target=httpd.serve_forever,daemon=True); thread.start()
        try:
            valid=context(ca_crt,control_crt,control_key)
            status=request(port,valid)
            record("Q10DH-01 trusted workload mTLS and SAN URI authorized control identity","HTTP 200",f"HTTP {status}","PASS" if status==200 else "FAIL")
            user=context(ca_crt,user_crt,user_key); status=request(port,user)
            record("Q10DH-02 CN spoof with wrong SAN URI","HTTP 403",f"HTTP {status}","PASS" if status==403 else "FAIL")
            POLICY["available"]=False; status=request(port,valid)
            record("Q10DH-03 policy dependency unavailable","HTTP 503 fail closed",f"HTTP {status}","PASS" if status==503 else "FAIL")
            POLICY["available"]=True
            # Client trusts the legitimate server CA, but presents a client cert from the rogue CA.
            untrusted=context(ca_crt,rogue_crt,rogue_key)
            before=TLS_EVIDENCE["server_handshake_rejections"]
            client_rejected=False
            try: request(port,untrusted)
            except (ssl.SSLError,OSError,http.client.HTTPException): client_rejected=True
            after=TLS_EVIDENCE["server_handshake_rejections"]
            server_rejected=after>before
            record("Q10DH-04 rogue client CA rejected by server with legal server trust","server rejection counter increases",f"client_error={client_rejected}; server_rejections_delta={after-before}; detail={TLS_EVIDENCE['last_rejection']}","PASS" if client_rejected and server_rejected else "FAIL")
        finally:
            httpd.shutdown(); httpd.server_close(); thread.join(timeout=2)
    # Egress tests use an in-lab sink; no external Internet dependency.
    sink_code=("import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
                "s.bind(('0.0.0.0',8443)); s.listen(20); s.settimeout(.5); end=time.time()+35;\n"
                "while time.time()<end:\n try: c,a=s.accept(); c.sendall(b'OK'); c.close()\n"
                " except socket.timeout: pass\n"
                "s.close()")
    sink=subprocess.Popen(["ip","netns","exec","rma10d-egress","python3","-c",sink_code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    control_handle=None
    try:
        sink_ready=False
        for _ in range(25):
            ready,detail=egress_probe("egress")
            if ready is True: sink_ready=True; break
            if sink.poll() is not None: break
            time.sleep(.1)
        record("Q10DH-05A controlled egress sink readiness","sink listener reachable inside sink namespace",detail,"PASS" if sink_ready else "FAIL")
        control_ok=False
        control_detail=detail if not sink_ready else 'positive control not yet run'
        if sink_ready:
            add=subprocess.run(["ip","netns","exec","rma10d-router","nft","insert","rule","inet","rma10d","forward",
                                "ip","saddr","10.20.1.2","ip","daddr","10.20.11.2","tcp","dport","8443","counter","accept",
                                "comment","RMA-EGRESS-POSITIVE-CONTROL"],capture_output=True,text=True)
            listing=subprocess.run(["ip","netns","exec","rma10d-router","nft","-a","list","chain","inet","rma10d","forward"],capture_output=True,text=True)
            import re
            match=re.search(r'comment "RMA-EGRESS-POSITIVE-CONTROL".*# handle (\d+)',listing.stdout)
            control_handle=int(match.group(1)) if match else None
            control_ok,control_detail=egress_probe("edge") if add.returncode==0 else (False,add.stderr[:240])
            if control_handle is not None:
                removed=subprocess.run(["ip","netns","exec","rma10d-router","nft","delete","rule","inet","rma10d","forward","handle",str(control_handle)],capture_output=True,text=True)
                if removed.returncode!=0: control_ok=False; control_detail+="; control rule removal failed: "+removed.stderr[:200]
            else:
                control_ok=False; control_detail+="; temporary allow-rule handle not found (lab will be torn down)"
        record("Q10DH-05B positive egress path control from edge","temporary exact allow rule permits sink connection",control_detail,"PASS" if control_ok else "FAIL")
        for zone in ZONES:
            before=nft_drop_packets()
            actual,detail=egress_probe(zone)
            after=nft_drop_packets()
            delta=(after-before) if before is not None and after is not None else None
            if not control_ok or delta is None:
                status="INCONCLUSIVE"
            elif actual is True:
                status="FAIL"
            elif delta>0:
                status="PASS"
            else:
                status="INCONCLUSIVE"
            record(f"Q10DH-05 external egress denied from {zone}","connection blocked and attributable nft forward-drop counter increases",
                   f"probe={actual}; drop_counter_delta={delta}; {detail}",status)
    finally:
        if sink.poll() is None: sink.terminate()
        try: sink.wait(timeout=2)
        except subprocess.TimeoutExpired: sink.kill()
    health_server=HTTPServer(("127.0.0.1",0),HealthHandler)
    health_thread=threading.Thread(target=health_server.serve_forever,daemon=True); health_thread.start()
    try:
        conn=http.client.HTTPConnection("127.0.0.1",health_server.server_address[1],timeout=2)
        conn.request("GET","/health"); response=conn.getresponse(); body=response.read(); live_ok=response.status==200 and body==b"healthy"; conn.close()
        record("Q10DH-06 live fresh health HTTP probe","HTTP 200 healthy",f"HTTP {response.status} {body.decode(errors='replace')}","PASS" if live_ok else "FAIL")
    finally:
        health_server.shutdown(); health_server.server_close(); health_thread.join(timeout=2)
    for age,expected in [(29.999,"HEALTHY"),(30.0,"HEALTHY"),(30.001,"UNKNOWN/STALE"),(-0.001,"ERROR")]:
        actual=health_freshness(age)
        record(f"Q10DH-07 health freshness boundary age={age}s",expected,actual,"PASS" if actual==expected else "FAIL")
    now=datetime.datetime.now(datetime.timezone.utc)
    out=os.path.join(os.environ.get("RUNNER_TEMP","/tmp"),"phase-a-stage10d-hardening-evidence.json")
    payload={"stage":"10D-Hardening","generated_at":now.isoformat(),"tests":RESULTS,"tls_evidence":TLS_EVIDENCE,
             "passed":sum(x["status"]=="PASS" for x in RESULTS),"failed":sum(x["status"]=="FAIL" for x in RESULTS),
             "inconclusive":sum(x["status"]=="INCONCLUSIVE" for x in RESULTS),
             "scope":"Disposable CI namespaces and localhost TLS lab only; external egress is INCONCLUSIVE without a controlled sink."}
    with open(out,"w",encoding="utf-8") as f: json.dump(payload,f,indent=2)
    print(f"Evidence written: {out}")
    print(f"Stage 10D-Hardening summary: PASS={payload['passed']} FAIL={payload['failed']} INCONCLUSIVE={payload['inconclusive']}")
    if payload["failed"] or payload["inconclusive"]: raise SystemExit(1)
if __name__=="__main__": main()
