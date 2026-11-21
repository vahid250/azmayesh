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
    # External internet probes are not evidence of firewall enforcement in this isolated lab.
    for zone in ZONES:
        record(f"Q10DH-05 external egress enforcement from {zone}","controlled external sink and attributable drop counter","no external sink/counter configured","INCONCLUSIVE")
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
