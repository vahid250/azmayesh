#!/usr/bin/env python3
"""Stage 10D Layer 01: isolated TLS CA trust and SAN URI workload identity tests."""
import http.client, pathlib, ssl, subprocess, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AUTHORIZED_URI = "spiffe://rma/control"
RESULTS = []
def openssl(*args):
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
def issue(d, name, ca_key, ca_crt, san, eku):
    key=d/f"{name}.key"; csr=d/f"{name}.csr"; crt=d/f"{name}.crt"; ext=d/f"{name}.ext"
    openssl("req","-new","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(csr),"-subj",f"/CN={name}")
    san_line=f"subjectAltName={san}\n" if san else ""
    ext.write_text(san_line+"keyUsage=critical,digitalSignature,keyEncipherment\n"+f"extendedKeyUsage={eku}\n",encoding="utf-8")
    openssl("x509","-req","-in",str(csr),"-CA",str(ca_crt),"-CAkey",str(ca_key),"-CAcreateserial","-out",str(crt),"-days","2","-sha256","-extfile",str(ext))
    return key,crt
def check(name, expected, actual):
    passed=expected==actual; RESULTS.append(passed)
    print(f"{'PASS' if passed else 'FAIL'} {name}: expected={expected}; actual={actual}")
    return passed
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        uris=[value for typ,value in self.connection.getpeercert().get("subjectAltName",()) if typ=="URI"]
        ok=AUTHORIZED_URI in uris
        self.send_response(200 if ok else 403); self.end_headers(); self.wfile.write(b"authorized" if ok else b"denied")
    def log_message(self,*args): pass
def client_ctx(ca, cert=None, key=None):
    c=ssl.create_default_context(cafile=str(ca))
    if cert: c.load_cert_chain(str(cert),str(key))
    return c
def request(port, context):
    conn=http.client.HTTPSConnection("localhost",port,context=context,timeout=3)
    try:
        conn.request("GET","/"); r=conn.getresponse(); body=r.read().decode(); return r.status,body
    finally: conn.close()
def main():
    with tempfile.TemporaryDirectory(prefix="stage10d-layer01-") as td:
        d=pathlib.Path(td); ca_key=d/"ca.key"; ca_crt=d/"ca.crt"
        openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(ca_key),"-out",str(ca_crt),"-days","2","-subj","/CN=Layer01-Test-CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign")
        server_key,server_crt=issue(d,"localhost",ca_key,ca_crt,"DNS:localhost","serverAuth")
        valid_key,valid_crt=issue(d,"control",ca_key,ca_crt,"URI:spiffe://rma/control","clientAuth")
        wrong_key,wrong_crt=issue(d,"wrong-workload",ca_key,ca_crt,"URI:spiffe://rma/user-api","clientAuth")
        missing_key,missing_crt=issue(d,"missing-san",ca_key,ca_crt,"","clientAuth")
        rogue=d/"rogue"; rogue.mkdir(); rkey=rogue/"ca.key"; rcrt=rogue/"ca.crt"
        openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(rkey),"-out",str(rcrt),"-days","2","-subj","/CN=Rogue-CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign")
        rogue_key,rogue_crt=issue(rogue,"rogue-control",rkey,rcrt,"URI:spiffe://rma/control","clientAuth")
        sctx=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH); sctx.load_cert_chain(str(server_crt),str(server_key)); sctx.load_verify_locations(cafile=str(ca_crt)); sctx.verify_mode=ssl.CERT_REQUIRED
        srv=ThreadingHTTPServer(("127.0.0.1",0),Handler); srv.socket=sctx.wrap_socket(srv.socket,server_side=True)
        t=threading.Thread(target=srv.serve_forever,daemon=True); t.start()
        try:
            port=srv.server_address[1]
            check("valid trusted client SAN identity",(200,"authorized"),request(port,client_ctx(ca_crt,valid_crt,valid_key)))
            check("trusted but wrong SAN identity",(403,"denied"),request(port,client_ctx(ca_crt,wrong_crt,wrong_key)))
            check("trusted client certificate missing SAN",(403,"denied"),request(port,client_ctx(ca_crt,missing_crt,missing_key)))
            rejected=False
            try: request(port,client_ctx(ca_crt,rogue_crt,rogue_key))
            except (ssl.SSLError,OSError,http.client.HTTPException): rejected=True
            check("rogue client CA rejected during TLS handshake",True,rejected)
        finally: srv.shutdown(); srv.server_close(); t.join(timeout=2)
    print(f"Layer 01 result: {sum(RESULTS)}/{len(RESULTS)} passed")
    if not all(RESULTS): raise SystemExit(1)
if __name__=="__main__": main()
