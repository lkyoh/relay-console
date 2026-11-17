"""Renew the certificate only while this standby is the public DNS entry."""
import json
import datetime
import os
from pathlib import Path
import socket
import subprocess
import time
from cryptography import x509
ROOT=Path('/etc/sbgateway-relay-manager')

def main():
    state=json.loads((ROOT/'state.json').read_text())
    if not state.get('tls_domain') or not (ROOT/'live.crt').exists():return
    addresses={v[4][0] for v in socket.getaddrinfo(state['public_host'],None,socket.AF_INET)}
    if addresses!={state['server_ip']}:return
    domain=state['tls_domain']
    cert=x509.load_pem_x509_certificate((ROOT/'live.crt').read_bytes())
    expiry=cert.not_valid_after_utc if hasattr(cert,'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if expiry.timestamp()-time.time()>30*86400:return
    result=subprocess.run(['certbot','certonly','--standalone','--non-interactive','--agree-tos',
        '--register-unsafely-without-email','--keep-until-expiring','--preferred-challenges','http',
        '--config-dir',str(ROOT/'acme'),'--work-dir',str(ROOT/'acme-work'),'--logs-dir',str(ROOT/'acme-log'),
        '--cert-name','sbgateway-relay-standby','-d',domain],capture_output=True,timeout=180)
    if result.returncode:raise RuntimeError('Certificate renewal failed; check public TCP port 80 and DNS')
    lineage=ROOT/'acme/live/sbgateway-relay-standby'
    for source,name in [('fullchain.pem','live.crt'),('privkey.pem','live.key')]:
        dest=ROOT/name;tmp=dest.with_suffix('.renew-new')
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'wb') as f:f.write((lineage/source).read_bytes())
        os.replace(tmp,dest)
    subprocess.run(['systemctl','try-restart','sbgateway-relay-managed','sbgateway-relay-manager'],check=True,timeout=60)

if __name__=='__main__':main()
