#!/usr/bin/env python3
"""Install a staged build on the Pi. Run with sudo from the extracted release."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=Path, help='release executable (default: krb-jwt-issuer next to deploy/)')
parser.add_argument('--sha256', help='expected SHA-256 of the executable, from the verified SHA256SUMS')
parser.add_argument('--host', required=True, help='public hostname, e.g. auth.example.com')
parser.add_argument('--realm', required=True, help='Kerberos realm, e.g. EXAMPLE.COM')
parser.add_argument('--subject', required=True, help='first allowed principal, e.g. alice@EXAMPLE.COM')
parser.add_argument('--audience', default='homelab-test')
parser.add_argument('--cert-dir', required=True, help='directory with fullchain.pem and privkey.pem')
parser.add_argument('--pihole-ip', help='also add a Pi-hole local DNS record host -> this address')
args = parser.parse_args()
assert os.geteuid() == 0
release = Path(__file__).resolve().parents[1]
backup = Path('/root') / ('krb-jwt-issuer-before-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
backup.mkdir(mode=0o700)

def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def install(source, dest, mode=0o644):
    target = Path(dest)
    if target.exists():
        saved = backup / target.relative_to('/')
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, saved)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)
    shutil.chown(target, user='root', group='root')

nginx = Path('/etc/nginx/conf.d/krb-jwt-issuer.conf')
assert not nginx.exists(), 'Existing issuer deployment: inspect before replacing'
assert not Path('/etc/krb-jwt-issuer/config.json').exists(), 'Existing issuer config: inspect before replacing'
if subprocess.run(['id', 'krb-jwt-issuer'], capture_output=True).returncode:
    run(['useradd', '--system', '--user-group', '--home-dir', '/var/lib/krb-jwt-issuer', '--no-create-home', '--shell', '/usr/sbin/nologin', 'krb-jwt-issuer'])
binary = args.binary or release / 'krb-jwt-issuer'
digest = hashlib.sha256(binary.read_bytes()).hexdigest()
print('Installing', binary, 'sha256', digest)
assert args.sha256 is None or digest == args.sha256.lower(), 'Executable does not match --sha256; refusing to install'
install(binary, '/usr/local/libexec/krb-jwt-issuer', 0o755)
config = json.loads((release / 'config.example.json').read_text())
config['issuer'] = 'https://' + args.host + '/issuer'
config['subjects'] = {args.subject: [args.audience]}
rendered = backup / 'config.json'
rendered.write_text(json.dumps(config, indent=2) + '\n')
install(rendered, '/etc/krb-jwt-issuer/config.json')
for unit in ['krb-jwt-issuer.socket', 'krb-jwt-issuer.service']:
    install(release / ('deploy/' + unit), '/etc/systemd/system/' + unit)

principal = 'HTTP/' + args.host
existing = run(['kadmin.local', '-q', 'getprinc ' + principal], capture_output=True, text=True)
if ('Principal: ' + principal + '@' + args.realm) not in existing.stdout:
    result = run(['kadmin.local', '-q', 'addprinc -randkey ' + principal], capture_output=True, text=True)
    assert 'created' in result.stdout, 'Could not create HTTP service principal'
keytab = Path('/etc/nginx/krb5-auth.keytab')
assert not keytab.exists(), 'Existing HTTP keytab: inspect before replacing'
result = run(['kadmin.local', '-q', 'ktadd -norandkey -k ' + str(keytab) + ' ' + principal], capture_output=True, text=True)
assert keytab.exists(), 'Could not export HTTP service key'
shutil.chown(keytab, user='root', group='www-data')
keytab.chmod(0o640)
template = (release / 'deploy/nginx.conf').read_text()
rendered = backup / 'nginx.conf'
rendered.write_text(template.replace('auth.example.com', args.host).replace('/etc/nginx/ssl/example.com', args.cert_dir.rstrip('/')))
install(rendered, str(nginx))
try:
    run(['nginx', '-t'])
except Exception:
    nginx.rename(backup / 'rejected-nginx.conf')
    raise
run(['systemctl', 'daemon-reload'])
run(['systemctl', 'enable', '--now', 'krb-jwt-issuer.socket'])
run(['systemctl', 'start', 'krb-jwt-issuer.service'])
run(['systemctl', 'reload', 'nginx'])

hostname = args.host
if args.pihole_ip:
    # Preserve the existing local DNS list and add the new auth hostname.
    pihole = Path('/etc/pihole/pihole.toml')
    shutil.copy2(pihole, backup / 'pihole.toml')
    hosts = tomllib.loads(pihole.read_text())['dns']['hosts']
    matches = [line for line in hosts if hostname in line.split()[1:]]
    assert not matches or all(line.split()[0] == args.pihole_ip for line in matches), 'Conflicting existing auth DNS record'
    if not matches:
        hosts.append(args.pihole_ip + ' ' + hostname)
        run(['pihole-FTL', '--config', 'dns.hosts', json.dumps(hosts)], capture_output=True)
        run(['pihole', 'reloaddns'])
print('Installed issuer. Configuration backup:', backup)
run(['systemctl', 'is-active', 'krb-jwt-issuer.socket', 'krb-jwt-issuer.service', 'nginx'])
if args.pihole_ip:
    run(['dig', '+time=3', '+tries=1', '@127.0.0.1', hostname, '+short'])
