#!/usr/bin/python3 -I
"""fake_igd_upgrade.py - a new version of fake-igd, put in by root (1.4.0).

Taken from otp's otp_upgrade.py, step for step. Neither the pages nor the
`upnp upgrade` command install anything themselves: the API runs as
`fake-igd`, which may not write a byte of the program. What it may do is lay
a package down in /var/lib/fake-igd/upgrade/ and ask for it with
request.json; systemd (fake-igd-upgrade.path) sees the request and starts
fake-igd-upgrade.service, which runs this as root. This then trusts nothing
it was handed:

  * the package is copied to a folder of root's own before anything is read
    from it, so it cannot be changed under the check;
  * it must be signed: MANIFEST lists the SHA-256 of every file, and
    MANIFEST.sig is the Ed25519 signature of MANIFEST by one of the keys in
    /opt/fake-igd/release-keys/ - which only root can write, and which
    only a package installed by root (install.sh, or this) puts there;
  * every file in it is listed in MANIFEST with the right hash, nothing more,
    no links, no device, no path outside its one folder;
  * it is not older than the version installed (the same one again is a
    retry and is allowed) - unless going back is asked for as such: on the
    command line, as root (--run FILE --downgrade), or from the pages (1.6.1,
    otp 1.0.143: request.json says "downgrade") - then never below the floor
    root keeps (downgrade-floor), and from the pages never below PAGES_FLOOR.

Then its own install.sh --upgrade --yes is run, exactly as somebody would
on the command line, and what it said is written back for the pages.

  fake_igd_upgrade.py                 serve request.json (as root, from systemd)
  fake_igd_upgrade.py --inspect FILE  check a package and say what it is (JSON);
                                      any user - the API and upnp ask this way
  fake_igd_upgrade.py --run FILE      check and put in a package by hand (root)
  fake_igd_upgrade.py --run FILE --downgrade   the same for an older one (root)
  ... --run FILE [--downgrade] --by WHO         who asked (upnp upgrade says who runs it)

While it runs, the pages are told how far it is (1.7.2) - the way otp's pages
are told a node is in maintenance: /var/www/fake-igd/.upgrade.json (root's,
readable by all, nothing secret in it; nginx never serves a name starting with
a dot) says the version, the step of install.sh and its words. The pages' PHP
reads it while fake-igd-api.service restarts, so the pages show the upgrade
going on - not "the API is not answering". install.sh --upgrade writes the
same file at each of its steps, also when it is run by hand. --run (upnp
upgrade ... --downgrade) is announced as one asked from the pages is: plan.json,
status.json and last.log beside the package, so the API's view says so too.
"""
import hashlib
import json
import os
import re
import select
import shutil
import stat
import signal
import subprocess
import threading
import sys
import tarfile
import tempfile
import time

STATE_DIR = os.environ.get('FAKE_IGD_STATE', '/var/lib/fake-igd')
UPGRADE_DIR = os.path.join(STATE_DIR, 'upgrade')
LIB_DIR = os.environ.get('FAKE_IGD_LIB', '/opt/fake-igd')
KEYS_DIR = os.environ.get('FAKE_IGD_RELEASE_KEYS', os.path.join(LIB_DIR, 'release-keys'))
MOST_PACKED = 64 * 1024 * 1024
MOST_UNPACKED = 256 * 1024 * 1024
MOST_FILES = 5000
INSTALL_LIMIT_S = 20 * 60      # under TimeoutStartSec=25min and the daemon's 30 (otp 1.0.59)
TOP = re.compile(r'^fake-igd-([0-9]+(?:\.[0-9]+){2,3})\Z')
WEB_DIR = os.environ.get('FAKE_IGD_WEB', '/var/www/fake-igd')
PAGES_FILE = os.path.join(WEB_DIR, '.upgrade.json')
FLOOR_FILE = os.path.join(LIB_DIR, 'downgrade-floor')
# The oldest version the pages may ask to go back to (1.6.1): the first with this helper, the
# release keys and the path unit - one older could not be brought up again from the pages.
PAGES_FLOOR = '1.4.0'


class Refused(Exception):
    pass


# The upgrade folder, opened once and used by its descriptor from then on
# (otp 1.0.44): the fake-igd account owns /var/lib/fake-igd, and could otherwise swap the
# folder for a link to anywhere between two steps of root's.
UP_FD = [None]


def up_fd():
    if UP_FD[0] is not None:
        return UP_FD[0]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    top = os.open(STATE_DIR, flags)
    try:
        fd = os.open('upgrade', flags, dir_fd=top)
    finally:
        os.close(top)
    st = os.fstat(fd)
    try:
        import pwd
        want = pwd.getpwnam('fake-igd').pw_uid
    except (KeyError, ImportError):
        want = st.st_uid
    if st.st_uid not in (0, want):
        os.close(fd)
        raise Refused('%s is owned by uid %d, not by fake-igd' % (UPGRADE_DIR, st.st_uid))
    UP_FD[0] = fd
    return fd


def _where(path):
    """(dir_fd, name) for a path in the upgrade folder, (None, path) else."""
    if os.path.dirname(path) == UPGRADE_DIR:
        return up_fd(), os.path.basename(path)
    return None, path


def version_tuple(v):
    return tuple(int(x) for x in str(v).split('.'))


def changelog_since(text, have, want, most=60000):
    """The sections of CHANGELOG.md newer than `have` up to `want`, newest first."""
    out = []
    for mm in re.finditer(r'^## ([0-9]+(?:\.[0-9]+)+)\b.*?(?=^## |\Z)', text, re.M | re.S):
        try:
            v = version_tuple(mm.group(1))
            if version_tuple(have) < v <= version_tuple(want):
                out.append(mm.group(0).strip())
        except (ValueError, TypeError):
            continue
    return '\n\n'.join(out)[:most]


def installed_version():
    try:
        with open(os.path.join(LIB_DIR, 'fake-igd.py'), encoding='utf-8') as f:
            for line in f:
                m = re.match(r"^__version__ = '([0-9.]+)'", line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return ''


def trusted_keys():
    try:
        names = sorted(n for n in os.listdir(KEYS_DIR) if n.endswith('.pub'))
    except OSError:
        names = []
    return [os.path.join(KEYS_DIR, n) for n in names]


def signed_by(manifest, signature):
    """The name of the trusted key that signed MANIFEST, or None."""
    for key in trusted_keys():
        try:
            r = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', key,
                                '-rawin', '-in', manifest, '-sigfile', signature],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        except (OSError, subprocess.SubprocessError):
            raise Refused('openssl is needed to check the signature, and it did not run')
        if r.returncode == 0:
            return os.path.basename(key)[:-4]
    return None


def inspect(path, extract_to=None):
    """Everything about a package that can be said without trusting it - and
    with extract_to, the package unpacked there once it has passed."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        raise Refused('the package cannot be read: %s' % e)
    if size > MOST_PACKED:
        raise Refused('the package is bigger than 64 MB, which no version of fake-igd is')
    try:
        tar = tarfile.open(path, 'r:gz')
    except (tarfile.TarError, OSError, EOFError) as e:
        raise Refused('that is not a .tar.gz: %s' % e)
    with tar:
        # Read one header at a time and stopped at the limit (otp 1.0.44):
        # getmembers() read every header first, millions of them if the
        # package said so, before anything was counted.
        members = []
        try:
            while True:
                one = tar.next()
                if one is None:
                    break
                members.append(one)
                if len(members) > MOST_FILES:
                    break
        except (tarfile.TarError, OSError, EOFError) as e:
            raise Refused('the package is damaged: %s' % e)
        if not members or len(members) > MOST_FILES:
            raise Refused('the package holds no files, or far too many')
        top = members[0].name.split('/')[0]
        m = TOP.match(top)
        if not m:
            raise Refused('the package is not a fake-igd release: its folder is "%s", not fake-igd-X.Y.Z'
                          % top[:80])
        version = m.group(1)
        files, total = {}, 0
        for one in members:
            name = one.name
            parts = name.split('/')
            if name.startswith('/') or '..' in parts or parts[0] != top or '\\' in name:
                raise Refused('the package has a path outside its folder: %s' % name[:120])
            if one.isdir():
                continue
            if not one.isreg():
                raise Refused('the package holds something that is not a plain file: %s'
                              % name[:120])
            total += one.size
            if total > MOST_UNPACKED:
                raise Refused('the package unpacks to more than 256 MB')
            rel = '/'.join(parts[1:])
            if rel in files:
                raise Refused('the package holds %s twice' % rel)
            files[rel] = one
        # A folder no file of the package is in is not taken (otp 1.0.209): the
        # signature covers the files, and an empty folder came in beside them.
        needed = {top}
        for rel in files:
            bits = rel.split('/')[:-1]
            for k in range(1, len(bits) + 1):
                needed.add(top + '/' + '/'.join(bits[:k]))
        for one in members:
            if one.isdir() and one.name.rstrip('/') not in needed:
                raise Refused('the package has a folder no file of it is in: %s' % one.name[:120])
        for need in ('MANIFEST', 'MANIFEST.sig', 'src/fake-igd.py', 'install.sh'):
            if need not in files:
                raise Refused('the package has no %s%s' % (need, ' - it is not signed'
                                                             if need.startswith('MANIFEST')
                                                             else ''))
        work = tempfile.mkdtemp(prefix='fake-igd-inspect-')
        try:
            man = os.path.join(work, 'MANIFEST')
            sig = os.path.join(work, 'MANIFEST.sig')
            for rel, dest in (('MANIFEST', man), ('MANIFEST.sig', sig)):
                if files[rel].size > 4 * 1024 * 1024:
                    raise Refused('%s is far too big' % rel)
                with tar.extractfile(files[rel]) as src, open(dest, 'wb') as out:
                    out.write(src.read())
            if not trusted_keys():
                raise Refused('no release key is installed on this machine (%s): upgrade once '
                              'on the command line with install.sh --upgrade' % KEYS_DIR)
            who = signed_by(man, sig)
            if not who:
                raise Refused('the signature is not by any release key this machine trusts - '
                              'a package that was changed, or signed by an unknown key. Put it '
                              'in on the command line (install.sh --upgrade) if you trust it.')
            listed = {}
            with open(man, encoding='utf-8') as f:
                for line in f:
                    line = line.rstrip('\n')
                    if not line.strip():
                        continue
                    mm = re.match(r'^([0-9a-f]{64})  (.+)\Z', line)
                    if not mm:
                        raise Refused('MANIFEST has a line that does not read')
                    listed[mm.group(2)] = mm.group(1)
            have = set(files) - {'MANIFEST', 'MANIFEST.sig'}
            if set(listed) != have:
                extra = sorted(have - set(listed))[:3]
                missing = sorted(set(listed) - have)[:3]
                raise Refused('the files are not the ones signed for%s%s' % (
                    (' - not signed: ' + ', '.join(extra)) if extra else '',
                    (' - missing: ' + ', '.join(missing)) if missing else ''))
            changelog = ''
            changelog_text = ''
            app_version = ''
            for rel in sorted(have):
                h = hashlib.sha256()
                keep = rel in ('CHANGELOG.md', 'src/fake-igd.py')
                body = []
                with tar.extractfile(files[rel]) as src:
                    while True:
                        lump = src.read(1 << 20)
                        if not lump:
                            break
                        h.update(lump)
                        if keep:
                            body.append(lump)
                if h.hexdigest() != listed[rel]:
                    raise Refused('%s is not the file that was signed' % rel)
                if rel == 'src/fake-igd.py':
                    mm = re.search(rb"^__version__ = '([0-9.]+)'", b''.join(body), re.M)
                    app_version = mm.group(1).decode() if mm else ''
                if rel == 'CHANGELOG.md':
                    changelog_text = b''.join(body).decode('utf-8', 'replace')
                    mm = re.search(r'^## %s\b.*?(?=^## |\Z)' % re.escape(version), changelog_text,
                                   re.M | re.S)
                    changelog = mm.group(0).strip()[:20000] if mm else ''
            if app_version != version:
                raise Refused('the folder says %s and src/fake-igd.py says %s' % (version, app_version))
            if extract_to:
                for one in members:
                    target = os.path.join(extract_to, one.name)
                    if one.isdir():
                        os.makedirs(target, mode=0o755, exist_ok=True)
                        continue
                    os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
                    with tar.extractfile(one) as src, \
                            open(target, 'xb') as out:
                        shutil.copyfileobj(src, out)
                    os.chmod(target, 0o755 if one.mode & 0o111 else 0o644)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    have_v = installed_version()
    # Every version between the one running and this one (otp 1.0.262): a node a few versions behind
    # was shown only the newest one's changes.
    if changelog_text and have_v:
        changelog = changelog_since(changelog_text, have_v, version) or changelog
    return {'version': version, 'top': top, 'files': len(have), 'signed_by': who,
            'bytes': size, 'changelog': changelog, 'installed': have_v,
            'newer': not have_v or version_tuple(version) > version_tuple(have_v),
            'older': bool(have_v) and version_tuple(version) < version_tuple(have_v)}


# ---- writing where fake-igd may also write: never through a link ----------------------
def write_safely(path, data, mode=0o640):
    """`data` into `path`, in a folder the fake-igd account owns: a new file made
    beside it and renamed over it, so a link put there in its place is
    replaced, never followed."""
    dfd, name = _where(path)
    folder = os.path.dirname(path)
    for _ in range(20):
        tmpname = '.%s.%d.%d' % (os.path.basename(path), os.getpid(),
                                 int(time.time() * 1e6) % 10 ** 9)
        tmp = tmpname if dfd is not None else os.path.join(folder, tmpname)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode,
                         dir_fd=dfd)
        except FileExistsError:
            continue
        with os.fdopen(fd, 'wb') as out:
            out.write(data if isinstance(data, bytes) else data.encode('utf-8'))
            try:
                os.fchown(out.fileno(), 0, _app_gid())
            except (OSError, KeyError):
                pass
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        return
    raise OSError('could not write %s' % path)


def _app_gid():
    import grp
    return grp.getgrnam('fake-igd').gr_gid


def read_small(path, most=65536):
    dfd, name = _where(path)
    # O_NONBLOCK: a FIFO put in its place does not hold root up (otp 1.0.44).
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise Refused('%s is not a file' % path)
    with os.fdopen(fd, 'rb') as f:
        return f.read(most + 1)[:most]


def status(**fields):
    fields['at'] = time.time()
    write_safely(os.path.join(UPGRADE_DIR, 'status.json'), json.dumps(fields))


# ---- the pages told (1.7.2): what otp's maintenance row is to its pages ----------------
PAGES = {}
STEP_LINE = re.compile(r'^==> (.*)$')
STEPS_IN = re.compile(r'^==> Upgrading fake-igd to \S+ \((\d+) steps\)')


def pages_say(**fields):
    """How far the upgrade is, into PAGES_FILE for the pages' PHP: root's, 0644, written
    beside it and renamed over it (a link put there is replaced, never followed). Never
    raises: the upgrade does not stop over the pages not being told."""
    PAGES.update(fields)
    PAGES['at'] = time.time()
    PAGES.setdefault('started', PAGES['at'])
    try:
        st = os.lstat(WEB_DIR)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
            return                      # no pages here, or not root's folder: nothing said
        data = json.dumps(PAGES).encode('utf-8')
        tmp = os.path.join(WEB_DIR, '.upgrade.%d.tmp' % os.getpid())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            os.fchmod(out.fileno(), 0o644)
        os.replace(tmp, PAGES_FILE)
    except OSError:
        pass


def pages_line(text):
    """A line of install.sh: its steps ("==> ...") counted for the pages."""
    m = STEPS_IN.match(text)
    if m:
        pages_say(parts=int(m.group(1)), part=0, words=text[4:].strip()[:160])
        return
    m = STEP_LINE.match(text)
    if m:
        pages_say(part=int(PAGES.get('part') or 0) + 1, words=m.group(1).strip()[:160])


def root_floor():
    """The oldest version this machine may go back to, or None."""
    try:
        fd = os.open(FLOOR_FILE, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            st = os.fstat(f.fileno())
            text = f.read(64).strip()
    except OSError:
        return None
    if st.st_uid != 0 or st.st_mode & 0o022 or not re.match(r'^\d+\.\d+\.\d+\Z', text):
        return None                     # not root's alone, or not a version: no floor
    return text


def put_in(package, ident='', want_sha='', by='the command line', log_to=None,
           downgrade=False, least=None):
    """Check the package and run its install.sh --upgrade. Returns (rc, log).
    `downgrade`: an older version is asked for on purpose."""
    if os.geteuid() != 0:
        raise Refused('putting a version in takes root')
    work = tempfile.mkdtemp(prefix='fake-igd-upgrade-', dir='/var/tmp')
    os.chmod(work, 0o700)
    lines = []

    def say(text):
        lines.append(text)
        if log_to:
            log_to(text)
    try:
        copy = os.path.join(work, 'package.tar.gz')
        pfd, pname = _where(package)
        fd = os.open(pname, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise Refused('the package is not a plain file')
        with os.fdopen(fd, 'rb') as src, open(copy, 'xb') as out:
            n = 0
            h = hashlib.sha256()
            while True:
                lump = src.read(1 << 20)
                if not lump:
                    break
                n += len(lump)
                if n > MOST_PACKED:
                    raise Refused('the package is bigger than 64 MB')
                h.update(lump)
                out.write(lump)
        if want_sha and h.hexdigest() != want_sha:
            raise Refused('the package is not the one that was checked on the pages '
                          '(its SHA-256 differs)')
        unpacked = os.path.join(work, 'x')
        os.makedirs(unpacked, mode=0o700)
        info = inspect(copy, extract_to=unpacked)
        if info['older']:
            if not downgrade:
                raise Refused('%s is older than %s, which is installed: going back is done as root on '
                              'the command line (upnp upgrade file FILE --downgrade)'
                              % (info['version'], info['installed']))
            floor = root_floor()
            if floor is not None and version_tuple(info['version']) < version_tuple(floor):
                raise Refused('%s is older than %s, the oldest the versions installed here '
                              'allow' % (info['version'], floor))
            if least and version_tuple(info['version']) < version_tuple(least):
                raise Refused('%s is older than %s: going back that far is done as root on the '
                              'command line (upnp upgrade file FILE --downgrade)'
                              % (info['version'], least))
            say('going back from %s to %s' % (info['installed'], info['version']))
        say('fake-igd %s, signed by %s, %d files - checked' % (info['version'], info['signed_by'],
                                                         info['files']))
        src = os.path.join(unpacked, info['top'])
        env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'LANG': 'C.UTF-8', 'FAKE_IGD_UPGRADE_FROM_PAGES': '1', 'TERM': 'dumb',
               'FAKE_IGD_UPGRADE_BY': str(by)[:100], 'FAKE_IGD_UPGRADE_ID': str(ident)[:64]}
        say('running %s/install.sh --upgrade --yes' % info['top'])
        p = subprocess.Popen(['bash', os.path.join(src, 'install.sh'), '--upgrade', '--yes'],
                             cwd=src, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True)
        # A deadline of its own (otp 1.0.59), under systemd's and the daemon's:
        # an install.sh that hangs (a dnf lock, a slow mirror) is stopped
        # here and said failed, not killed with the status left "running".
        late = []

        def too_long():
            # The whole group (otp 1.0.136): bash killed alone left dnf or cp
            # running with the pipe open - the loop below never ended - and
            # install.sh's own put-back (its EXIT trap) never ran. TERM
            # first, so the trap runs; KILL after half a minute.
            late.append(time.time())
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except OSError:
                pass

            def hard():
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
            t = threading.Timer(30, hard)
            t.daemon = True
            t.start()
        dog = threading.Timer(INSTALL_LIMIT_S, too_long)
        dog.daemon = True
        dog.start()

        def stopped(_sig, _frame):
            too_long()
            raise Refused('fake-igd-upgrade.service was stopped while install.sh ran')
        signal.signal(signal.SIGTERM, stopped)
        try:
            # Read with select (otp 1.0.136): a read that blocks cannot be ended
            # from another thread, and something outside the group holding
            # the pipe kept it open. Once the deadline killed the group, at
            # most 35 s more are waited for its last lines.
            fd = p.stdout.fileno()
            buf = b''
            while True:
                if late and time.time() - late[0] > 35:
                    break
                r, _w, _x = select.select([fd], [], [], 1.0)
                if not r:
                    if p.poll() is not None:
                        # install.sh ended and nothing more came for a second:
                        # done, whatever else still holds the pipe.
                        break
                    continue
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b'\n' in buf:
                    raw, buf = buf.split(b'\n', 1)
                    say(re.sub(r'\x1b\[[0-9;]*m', '', raw.decode('utf-8', 'replace')))
            if buf:
                say(re.sub(r'\x1b\[[0-9;]*m', '', buf.decode('utf-8', 'replace')))
            rc = p.wait()
        finally:
            dog.cancel()
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
        if late:
            raise Refused('install.sh did not finish in %d min and was stopped'
                          % (INSTALL_LIMIT_S // 60))
        say('install.sh ended with %d' % rc)
        return rc, info, lines
    finally:
        shutil.rmtree(work, ignore_errors=True)


def serve_request():
    """What systemd starts when request.json appears."""
    req = os.path.join(UPGRADE_DIR, 'request.json')
    taken = os.path.join(UPGRADE_DIR, 'request.taken')
    try:
        dfd = up_fd()
        os.replace('request.json', 'request.taken', src_dir_fd=dfd, dst_dir_fd=dfd)
    except FileNotFoundError:
        return 0
    except OSError:
        # Something there that is no file (otp 1.0.94): moved aside, so the path
        # unit does not start this again and again until systemd gives up.
        if 'dfd' not in locals():
            return 1
        for name in ('request.taken', 'request.json'):
            try:
                os.unlink(name, dir_fd=dfd)
            except FileNotFoundError:
                continue
            except OSError:
                try:
                    os.rename(name, '.refused-%s-%d' % (name, int(time.time())),
                              src_dir_fd=dfd, dst_dir_fd=dfd)
                except OSError:
                    pass
        return 1
    ident = ''
    try:
        try:
            r = json.loads(read_small(taken).decode('utf-8'))
        except (ValueError, OSError) as e:
            raise Refused('the request does not read: %s' % e)
        ident = str(r.get('id') or '')[:64]
        name = os.path.basename(str(r.get('file') or ''))
        if not re.match(r'^fake-igd-[0-9.]+\.tar\.gz\Z', name):
            raise Refused('the request names no package')
    except Refused as e:
        status(id=ident, state='failed', rc=-1, said=str(e), tail=['refused: %s' % e])
        pages_say(id=ident, state='failed', said=str(e), words='refused')
        _drop_taken()
        return 0
    down = r.get('downgrade') is True
    try:
        announced_run(os.path.join(UPGRADE_DIR, name), ident, r.get('version'), str(r.get('sha') or ''),
                      r.get('by') or 'the pages', down, PAGES_FLOOR if down else None)
    finally:
        _drop_taken()
    return 0


def _drop_taken():
    try:
        os.unlink('request.taken', dir_fd=up_fd())
    except (OSError, Refused):
        pass


def announced_run(package, ident, version, sha='', by='the pages', down=False, least=None,
                  echo=None):
    """install.sh --upgrade of `package`, said as it goes: status.json and last.log for the API
    and `upnp upgrade follow`, PAGES_FILE for the pages while the API restarts. Returns rc."""
    log_path = os.path.join(UPGRADE_DIR, 'last.log')
    log_lines = []
    last_flush = [0.0]

    def log_to(text):
        log_lines.append(text)
        if echo:
            echo(text)
        pages_line(text)
        if time.time() - last_flush[0] > 2:
            last_flush[0] = time.time()
            try:
                write_safely(log_path, '\n'.join(log_lines[-4000:]) + '\n')
            except OSError:
                pass
    rc = -1
    PAGES.clear()
    pages_say(id=ident, state='running', version=version, by=str(by or '')[:100], downgrade=bool(down),
              **{'from': installed_version()}, part=0, parts=0, words='root checks the package')
    try:
        status(id=ident, state='running', version=version, pid=os.getpid(), downgrade=down)
        rc, info, _ = put_in(package, ident, sha, by, log_to, downgrade=down, least=least)
        status(id=ident, state='done' if rc == 0 else 'failed', rc=rc,
               version=info['version'], tail=log_lines[-40:], downgrade=down)
        pages_say(state='done' if rc == 0 else 'failed', version=info['version'],
                  part=PAGES.get('parts') if rc == 0 else PAGES.get('part'),
                  said='' if rc == 0 else 'install.sh ended with %d' % rc,
                  words='fake-igd %s runs' % info['version'] if rc == 0 else 'install.sh ended with %d' % rc)
    except Refused as e:
        log_to('refused: %s' % e)
        status(id=ident, state='failed', rc=-1, said=str(e), tail=log_lines[-40:])
        pages_say(state='failed', said=str(e), words='refused')
    except Exception as e:                       # noqa: BLE001 - said, never lost
        log_to('broke: %s' % e)
        status(id=ident, state='failed', rc=-2, said='the upgrade broke: %s' % e,
               tail=log_lines[-40:])
        pages_say(state='failed', said='the upgrade broke: %s' % e, words='broke')
    finally:
        last_flush[0] = 0
        try:
            write_safely(log_path, '\n'.join(log_lines[-4000:]) + '\n')
        except OSError:
            pass
    return rc


def run_by_hand(path, down, by):
    """--run: as root on the command line (upnp upgrade file ... --downgrade). Announced as one
    asked from the pages is (1.7.2): plan.json and status.json beside the packages - the API's
    view, the overview, upnp upgrade status - and PAGES_FILE, the pages while the API restarts."""
    if os.geteuid() != 0:
        print('refused: putting a version in takes root')
        return 1
    try:
        info = inspect(path)
    except Refused as e:
        print('refused: %s' % e)
        return 1
    ident = '%d-cli%04x' % (int(time.time()), os.getpid() & 0xffff)
    try:
        up_fd()
        write_safely(os.path.join(UPGRADE_DIR, 'plan.json'), json.dumps({
            'id': ident, 'version': info['version'], 'by': str(by)[:100], 'at': time.time(),
            'downgrade': bool(down), 'from_version': info.get('installed') or '',
            'signed_by': info.get('signed_by') or '', 'cli': True}))
    except (OSError, Refused) as e:
        print('note: the pages are not told (%s)' % e)
    return announced_run(path, ident, info['version'], by=by, down=down, echo=print)


def main(argv):
    if len(argv) >= 2 and argv[0] == '--inspect':
        try:
            print(json.dumps(dict(inspect(argv[1]), ok=True)))
        except Refused as e:
            print(json.dumps({'ok': False, 'said': str(e)}))
        return 0
    if len(argv) >= 2 and argv[0] == '--run':
        by = 'the command line'
        if '--by' in argv[2:]:
            i = argv.index('--by', 2)
            by = argv[i + 1] if i + 1 < len(argv) else by
        rc = run_by_hand(os.path.abspath(argv[1]), '--downgrade' in argv[2:], by)
        return 1 if rc < 0 else rc
    if not argv:
        return serve_request()
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
