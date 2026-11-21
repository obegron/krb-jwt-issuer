#!/usr/bin/env python3
"""Install or upgrade krb-jwt-issuer on the host that runs nginx.

Run as root from the extracted, verified release directory:

  fresh install:  sudo python3 deploy/install.py --host H --realm R --subject P --cert-dir D
  upgrade:        sudo python3 deploy/install.py --upgrade [--host H --cert-dir D]

All pre-flight checks run before anything is changed. If a later step fails,
files this run installed are restored or removed (originals are also copied to
/root/krb-jwt-issuer-before-<timestamp>/).
"""
import argparse
import datetime
import hashlib
import json
import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

SERVICE_USER = 'krb-jwt-issuer'
BINARY_DEST = Path('/usr/local/libexec/krb-jwt-issuer')
CONFIG_DEST = Path('/etc/krb-jwt-issuer/config.json')
STATE_DIR = Path('/var/lib/krb-jwt-issuer')
NGINX_CONF = Path('/etc/nginx/conf.d/krb-jwt-issuer.conf')
KEYTAB = Path('/etc/nginx/krb5-auth.keytab')
UNITS = ['krb-jwt-issuer.socket', 'krb-jwt-issuer.service']


def die(message):
    # Not an assert: asserts disappear under python -O.
    sys.exit('error: ' + message)


def run(args, check=True, **kwargs):
    return subprocess.run(args, check=check, **kwargs)


parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--upgrade', action='store_true', help='replace binary and units only; keep config, signing key and keytab')
parser.add_argument('--host', help='public hostname, e.g. auth.example.com')
parser.add_argument('--realm', help='Kerberos realm, e.g. EXAMPLE.COM')
parser.add_argument('--subject', help='first allowed principal, e.g. alice@EXAMPLE.COM')
parser.add_argument('--audience', default='homelab-test', help='audience that principal may request (default: %(default)s)')
parser.add_argument('--cert-dir', help='directory containing fullchain.pem and privkey.pem')
parser.add_argument('--keytab', type=Path, help='existing keytab for HTTP/<host> (use when the KDC is on another machine); default: create it with kadmin.local')
parser.add_argument('--nginx-user', help='user nginx workers run as (default: www-data; "nginx" on RHEL/Arch). On --upgrade the installed socket unit\'s owner is kept unless given.')
parser.add_argument('--binary', type=Path, help='release executable (default: krb-jwt-issuer next to deploy/)')
parser.add_argument('--sha256', help='expected SHA-256 of the executable, from the verified SHA256SUMS')
parser.add_argument('--pihole-ip', help='also add a Pi-hole local DNS record host -> this address')
args = parser.parse_args()

release = Path(__file__).resolve().parents[1]
binary = args.binary or release / 'krb-jwt-issuer'
backup = Path('/root') / ('krb-jwt-issuer-before-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
undo = []  # callables that revert this run's changes, newest first


def installed_socket_user():
    try:
        for line in Path('/etc/systemd/system/krb-jwt-issuer.socket').read_text().splitlines():
            if line.startswith('SocketUser='):
                return line.split('=', 1)[1].strip()
    except OSError:
        pass
    return None


if not args.nginx_user:
    args.nginx_user = (installed_socket_user() if args.upgrade else None) or 'www-data'


def preflight():
    if os.geteuid() != 0:
        die('run as root (sudo)')
    if not binary.is_file():
        die('executable not found: %s (run from the extracted release or pass --binary)' % binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    print('Executable', binary, 'sha256', digest)
    if args.sha256 and digest != args.sha256.lower():
        die('executable does not match --sha256; refusing to install')
    for tool in ('systemctl', 'nginx'):
        if not shutil.which(tool):
            die(tool + ' not found')
    try:
        pwd.getpwnam(args.nginx_user)
    except KeyError:
        die('user %r does not exist; pass --nginx-user with the account nginx runs as' % args.nginx_user)
    if args.pihole_ip and sys.version_info < (3, 11):
        die('--pihole-ip needs Python 3.11+ (tomllib); add the DNS record by hand instead')
    if args.upgrade:
        if not CONFIG_DEST.exists() or not NGINX_CONF.exists():
            die('nothing to upgrade: %s or %s is missing; do a fresh install' % (CONFIG_DEST, NGINX_CONF))
        if bool(args.host) != bool(args.cert_dir):
            die('--host and --cert-dir are used together, to re-render the nginx config')
        return
    missing = [n for n in ('host', 'realm', 'subject', 'cert_dir') if not getattr(args, n)]
    if missing:
        die('a fresh install needs --' + ', --'.join(m.replace('_', '-') for m in missing))
    for name in ('fullchain.pem', 'privkey.pem'):
        if not (Path(args.cert_dir) / name).is_file():
            die('%s not found in %s' % (name, args.cert_dir))
    if NGINX_CONF.exists() or CONFIG_DEST.exists() or KEYTAB.exists():
        die('an existing deployment was found (%s, %s or %s). Use --upgrade, or inspect and remove it first.' % (NGINX_CONF, CONFIG_DEST, KEYTAB))
    if args.keytab:
        if not args.keytab.is_file():
            die('keytab not found: %s' % args.keytab)
    elif not shutil.which('kadmin.local'):
        die('kadmin.local not found: the KDC is not on this host. Create the HTTP/%s keytab on the KDC and pass it with --keytab.' % args.host)


def install(source, dest, mode=0o644, owner=('root', 'root')):
    """Atomically place a file, remembering how to put the previous state back."""
    dest = Path(dest)
    saved = None
    if dest.exists():
        saved = backup / dest.relative_to('/')
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dest, saved)
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = dest.with_name(dest.name + '.new')
    shutil.copyfile(source, staging)
    staging.chmod(mode)
    shutil.chown(staging, user=owner[0], group=owner[1])
    os.replace(staging, dest)  # replacing a running executable is safe with rename

    def revert():
        if saved:
            # Never write into the file in place: a running executable cannot be
            # opened for writing (ETXTBSY). Stage a copy and rename over it.
            shutil.copy2(saved, staging)
            os.replace(staging, dest)
        else:
            dest.unlink(missing_ok=True)
    undo.append(revert)


def render(name, text):
    path = backup / 'rendered' / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def units():
    for unit in UNITS:
        text = (release / 'deploy' / unit).read_text()
        text = text.replace('SocketUser=www-data', 'SocketUser=' + args.nginx_user).replace('SocketGroup=www-data', 'SocketGroup=' + args.nginx_user)
        install(render(unit, text), '/etc/systemd/system/' + unit)


def nginx_conf():
    text = (release / 'deploy/nginx.conf').read_text()
    text = text.replace('auth.example.com', args.host).replace('/etc/nginx/ssl/example.com', args.cert_dir.rstrip('/'))
    install(render('nginx.conf', text), NGINX_CONF)
    result = run(['nginx', '-t'], check=False, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('nginx rejected the new configuration (is the auth_gss / SPNEGO module installed and loaded?):\n' + result.stderr)


def create_keytab():
    principal = 'HTTP/' + args.host
    if args.keytab:
        install(args.keytab, KEYTAB, 0o640, ('root', args.nginx_user))
        return
    have = lambda: ('Principal: %s@%s' % (principal, args.realm)) in run(['kadmin.local', '-q', 'getprinc ' + principal], check=False, capture_output=True, text=True).stdout
    if not have():
        run(['kadmin.local', '-q', 'addprinc -randkey ' + principal], check=False, capture_output=True, text=True)
        if not have():
            raise RuntimeError('could not create the %s service principal with kadmin.local (is the realm %s correct?)' % (principal, args.realm))
    result = run(['kadmin.local', '-q', 'ktadd -norandkey -k %s %s' % (KEYTAB, principal)], check=False, capture_output=True, text=True)
    if not KEYTAB.exists():
        raise RuntimeError('could not export the service key: ' + result.stdout + result.stderr)
    undo.append(lambda: KEYTAB.unlink(missing_ok=True))
    shutil.chown(KEYTAB, user='root', group=args.nginx_user)
    KEYTAB.chmod(0o640)


def fresh_install():
    if subprocess.run(['id', SERVICE_USER], capture_output=True).returncode:
        run(['useradd', '--system', '--user-group', '--home-dir', str(STATE_DIR), '--no-create-home', '--shell', '/usr/sbin/nologin', SERVICE_USER])
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    shutil.chown(STATE_DIR, user=SERVICE_USER, group=SERVICE_USER)
    install(binary, BINARY_DEST, 0o755)
    config = json.loads((release / 'config.example.json').read_text())
    config['issuer'] = 'https://' + args.host + '/issuer'
    config['subjects'] = {args.subject: [args.audience]}
    install(render('config.json', json.dumps(config, indent=2) + '\n'), CONFIG_DEST)
    units()
    create_keytab()
    # The signing key is created explicitly, as the service user and ahead of the
    # first request (generating a 3072-bit key can take a while on a Pi).
    key = STATE_DIR / 'signing.key.pem'
    if not key.exists():
        run(['runuser', '-u', SERVICE_USER, '--', str(BINARY_DEST), '-config', str(CONFIG_DEST), '-init-key'])
    nginx_conf()
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'krb-jwt-issuer.socket'])
    undo.append(lambda: run(['systemctl', 'disable', '--now', 'krb-jwt-issuer.socket'], check=False))
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'krb-jwt-issuer.socket']).returncode:
        raise RuntimeError('the socket unit did not start; see: systemctl status krb-jwt-issuer.socket')
    run(['systemctl', 'reload', 'nginx'])


def upgrade():
    install(binary, BINARY_DEST, 0o755)
    units()
    if args.host:
        nginx_conf()
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'restart', 'krb-jwt-issuer.socket'])
    run(['systemctl', 'restart', 'krb-jwt-issuer.service'])
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'krb-jwt-issuer.service']).returncode:
        raise RuntimeError('the new version did not start; see: journalctl -u krb-jwt-issuer')
    run(['systemctl', 'reload', 'nginx'])


def add_pihole_record():
    import tomllib  # Python 3.11+, only needed here
    pihole = Path('/etc/pihole/pihole.toml')
    shutil.copy2(pihole, backup / 'pihole.toml')
    hosts = tomllib.loads(pihole.read_text())['dns']['hosts']
    matches = [line for line in hosts if args.host in line.split()[1:]]
    if matches and not all(line.split()[0] == args.pihole_ip for line in matches):
        die('conflicting Pi-hole DNS record for ' + args.host)
    if not matches:
        hosts.append(args.pihole_ip + ' ' + args.host)
        run(['pihole-FTL', '--config', 'dns.hosts', json.dumps(hosts)], capture_output=True)
        run(['pihole', 'reloaddns'])


preflight()
backup.mkdir(mode=0o700)
try:
    upgrade() if args.upgrade else fresh_install()
except BaseException as error:
    print('\nFAILED: %s\nRolling back this run\'s changes...' % error, file=sys.stderr)
    for revert in reversed(undo):
        try:
            revert()
        except Exception as problem:
            print('  rollback step failed:', problem, file=sys.stderr)
    run(['systemctl', 'daemon-reload'], check=False)
    run(['systemctl', 'restart', 'krb-jwt-issuer.service'], check=False) if args.upgrade else None
    print('Originals are kept in %s. Fix the problem and run again.' % backup, file=sys.stderr)
    if not args.upgrade:
        print('Left in place on purpose: the %s account, %s (including any signing key; a re-run reuses it)\n'
              'and the HTTP/%s principal in the KDC (only the exported keytab was removed).' % (SERVICE_USER, STATE_DIR, args.host), file=sys.stderr)
    sys.exit(1)

if args.pihole_ip:
    try:
        add_pihole_record()
    except BaseException as problem:  # the issuer itself is installed and working
        print('WARNING: installed, but the Pi-hole DNS record was not added: %s\nAdd it by hand: %s %s' % (problem, args.pihole_ip, args.host), file=sys.stderr)

print('\nInstalled. Backups: %s' % backup)
host = args.host
if not host:
    host = json.loads(CONFIG_DEST.read_text())['issuer'].split('/')[2]
url = 'https://%s/issuer' % host
public = run([str(BINARY_DEST), 'check', '-url', url, '-public-only'], check=False)
if public.returncode:
    print('\nWARNING: the public check failed. If this host cannot resolve or trust %s that is expected;\n'
          'otherwise look at: systemctl status krb-jwt-issuer.socket krb-jwt-issuer.service; nginx -t' % host, file=sys.stderr)
print('\nNext, from a machine that resolves %s and has a Kerberos ticket (kinit first):' % host)
print('  krb-jwt-issuer check -url %s -audience %s' % (url, args.audience))
