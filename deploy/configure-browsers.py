#!/usr/bin/env python3
"""Run through pkexec on the desktop to trust the new Kerberos hostname."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--host', required=True, help='issuer hostname, e.g. auth.example.com')
parser.add_argument('--hosts-ip', help='also add an /etc/hosts entry host -> this address')
args = parser.parse_args()
assert os.geteuid() == 0
backup = Path('/root') / ('krb-jwt-issuer-client-before-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
backup.mkdir(mode=0o700)

def write(path, data):
    path = Path(path)
    if path.exists():
        saved = backup / path.relative_to('/')
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, saved)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)
    path.chmod(0o644)

firefox = Path('/etc/firefox/policies/policies.json')
data = json.loads(firefox.read_text())
trusted = data.setdefault('policies', {}).setdefault('Authentication', {}).setdefault('SPNEGO', [])
site = 'https://' + args.host
if site not in trusted:
    trusted.append(site)
write(firefox, json.dumps(data, indent=2)+'\n')

brave = Path('/etc/brave/policies/managed/kerberos.json')
data = json.loads(brave.read_text())
trusted = [name.strip() for name in data.get('AuthServerAllowlist','').split(',') if name.strip()]
if args.host not in trusted:
    trusted.append(args.host)
data['AuthServerAllowlist'] = ','.join(trusted)
data['DisableAuthNegotiateCnameLookup'] = True
write(brave, json.dumps(data, indent=2)+'\n')

if args.hosts_ip:
    hosts = Path('/etc/hosts').read_text()
    if args.host not in hosts:
        write('/etc/hosts', hosts.rstrip() + '\n' + args.hosts_ip + ' ' + args.host + '\n')
print('Added auth hostname to Firefox, Brave, and local name resolution. Backup:', backup)
