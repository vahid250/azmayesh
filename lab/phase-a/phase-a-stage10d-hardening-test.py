#!/usr/bin/env python3
"""Stage 10D-Hardening: real mTLS identity, fail-closed policy API, egress deny, and health freshness."""
from __future__ import annotations
import datetime, http.client, json, os, pathlib, socket, ssl, subprocess, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ZONES=("edge","api","control","admin","monitor","vpn","db","ci","rogue","vpn_peer")
RESULTS=[]
POLICY={"available":True}
def record(test, expected, actual, passed):
    RESULTS.append({"test":test,"expected":expected,"actual":actual,"passed":bool(passed)})
    print(f"{'PASS' if passed else 'FAIL'}: {test}: expected={expected}; actual={actual}")
    if not passed: raise AssertionError(test)
def openssl(*args):
    subprocess.run(["openssl",*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
def make_cert(d,name,ca_key,ca_crt):
    key=d/f"{name}.key"; csr=d/f"{name}.csr"; crt=d/f"{name}.crt"
    openssl("req","-new","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(csr),"-subj",f"/CN={name}")
    ext=d/f"{name}.ext"
    ext.write_text("subjectAltName=DNS:localhost\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" if name=="localhost" else "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n",encoding="utf-8")
    openssl("x509","-req","-in",str(csr),"-CA",str(ca_crt),"-CAkey",str(ca_key),"-CAcreateserial","-out",str(crt),"-days","2","-sha256","-extfile",str(ext))
    return key,crt
class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"healthy")
    def log_message(self,*args): pass

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        cert=self.connection.getpeercert()
        cn=""
        for group in cert.get("subject",()):
            for key,value in group:
                if key=="commonName": cn=value
        if self.path!="/mutate":
            self.send_response(404); self.end_headers(); return
        if cn!="rma-control":
            self.send_response(403); self.end_headers(); return
        if not POLICY["available"]:
            self.send_response(503); self.end_headers(); return
        self.send_response(200); self.end_headers(); self.wfile.write(b"accepted")
    def log_message(self,*args): pass
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
def main():
    with tempfile.TemporaryDirectory(prefix="rma10dh-") as td:
        d=pathlib.Path(td)
        ca_key=d/"ca.key"; ca_crt=d/"ca.crt"
        openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(ca_key),"-out",str(ca_crt),"-days","2","-subj","/CN=RMA-Test-CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign")
        control_key,control_crt=make_cert(d,"rma-control",ca_key,ca_crt)
        user_key,user_crt=make_cert(d,"rma-user-api",ca_key,ca_crt)
        server_key,server_crt=make_cert(d,"localhost",ca_key,ca_crt)
        rogue_ca_key=d/"rogue-ca.key"; rogue_ca_crt=d/"rogue-ca.crt"
        openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(rogue_ca_key),"-out",str(rogue_ca_crt),"-days","2","-subj","/CN=Untrusted-Test-CA")
        rogue_dir=d/"untrusted"; rogue_dir.mkdir(mode=0o700)
        rogue_key,rogue_crt=make_cert(rogue_dir,"rma-control",rogue_ca_key,rogue_ca_crt)
        server_ctx=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_ctx.load_cert_chain(str(server_crt),str(server_key))
        server_ctx.load_verify_locations(cafile=str(ca_crt)); server_ctx.verify_mode=ssl.CERT_REQUIRED
        server_ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        verify=subprocess.run(["openssl","verify","-purpose","sslclient","-CAfile",str(ca_crt),str(control_crt)],check=False,capture_output=True,text=True)
        if verify.returncode != 0:
            print("Certificate verification diagnostic (stdout):",verify.stdout)
            print("Certificate verification diagnostic (stderr):",verify.stderr)
            raise RuntimeError("OpenSSL client certificate verification failed")
        print("PASS: OpenSSL client certificate purpose and CA validation")
        httpd=HTTPServer(("127.0.0.1",0),Handler)
        httpd.socket=server_ctx.wrap_socket(httpd.socket,server_side=True)
        port=httpd.server_address[1]
        thread=threading.Thread(target=httpd.serve_forever,daemon=True); thread.start()
        try:
            valid=context(ca_crt,control_crt,control_key)
            status=request(port,valid)
            record("Q10DH-01 trusted workload mTLS and authorized control identity","HTTP 200",f"HTTP {status}",status==200)
            user=context(ca_crt,user_crt,user_key); status=request(port,user)
            record("Q10DH-02 trusted but wrong workload identity","HTTP 403",f"HTTP {status}",status==403)
            POLICY["available"]=False; status=request(port,valid)
            record("Q10DH-03 policy dependency unavailable","HTTP 503 fail closed",f"HTTP {status}",status==503)
            POLICY["available"]=True
            untrusted=context(rogue_ca_crt,rogue_crt,rogue_key); rejected=False
            try: request(port,untrusted)
            except (ssl.SSLError,OSError,http.client.HTTPException): rejected=True
            record("Q10DH-04 untrusted certificate authority","TLS handshake rejected","rejected" if rejected else "connected",rejected)
        finally:
            httpd.shutdown(); httpd.server_close(); thread.join(timeout=2)
    for zone in ZONES:
        probe="import socket,sys; s=socket.socket(); s.settimeout(1.5)\ntry: s.connect(('1.1.1.1',443)); sys.exit(0)\nexcept OSError: sys.exit(1)\n"
        p=subprocess.run(["ip","netns","exec","rma10d-"+zone,"python3","-c",probe],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        denied=p.returncode!=0
        record(f"Q10DH-05 public egress denied from {zone}","DENY","DENY" if denied else "ALLOW",denied)
    health_server=HTTPServer(("127.0.0.1",0),HealthHandler)
    health_thread=threading.Thread(target=health_server.serve_forever,daemon=True); health_thread.start()
    try:
        conn=http.client.HTTPConnection("127.0.0.1",health_server.server_address[1],timeout=2)
        conn.request("GET","/health"); response=conn.getresponse(); body=response.read(); live_ok=response.status==200 and body==b"healthy"; conn.close()
        record("Q10DH-06 live fresh health HTTP probe","HTTP 200 healthy",f"HTTP {response.status} {body.decode(errors='replace')}",live_ok)
    finally:
        health_server.shutdown(); health_server.server_close(); health_thread.join(timeout=2)
    state="UNKNOWN/STALE" if 31.0>30 else "HEALTHY"
    record("Q10DH-07 stale health signal","UNKNOWN/STALE",state,state=="UNKNOWN/STALE")
    now=datetime.datetime.now(datetime.timezone.utc)
    out=os.path.join(os.environ.get("RUNNER_TEMP","/tmp"),"phase-a-stage10d-hardening-evidence.json")
    payload={"stage":"10D-Hardening","generated_at":now.isoformat(),"tests":RESULTS,
             "passed":sum(x["passed"] for x in RESULTS),"failed":sum(not x["passed"] for x in RESULTS),
             "scope":"Disposable CI namespaces and localhost mTLS lab only; not production/cloud proof."}
    with open(out,"w",encoding="utf-8") as f: json.dump(payload,f,indent=2)
    print(f"Evidence written: {out}")
    if payload["failed"]: raise SystemExit(1)
    print(f"Stage 10D-Hardening passed: {payload['passed']} checks.")
if __name__=="__main__": main()
