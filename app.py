#!/usr/bin/env python3
"""
NetVentoy — Network PXE/HTTP boot server with web UI.
Debian 13 (Trixie) compatible: uses only packages available via apt.

Boot chain:
  EFI  (Secure Boot): shimx64.efi (MS-trusted) → grubnetx64.efi (distro-signed) → grub.cfg
  EFI  (HTTP Boot):   shimx64.efi over HTTP     → grubnetx64.efi over HTTP       → grub.cfg
  BIOS:               grub i386-pc core.0 (TFTP) → grub.cfg

apt dependencies:
    python3-flask  python3-werkzeug  python3-watchdog
    dnsmasq  xorriso  grub-efi-amd64-signed  shim-signed  grub-pc-bin

No pip required.
"""

import os, json, subprocess, threading, hashlib, shutil, signal, time
import sys, time, re, socket, logging, tempfile
from pathlib import Path
from http import HTTPStatus

from flask import Flask, render_template, request, jsonify, send_from_directory, Response
from werkzeug.utils import secure_filename
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger('netventoy')

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR     = Path(os.environ.get('NETVENTOY_DIR', Path(__file__).parent)).resolve()
ISO_DIR      = BASE_DIR / 'isos'
TFTP_DIR     = BASE_DIR / 'tftp'
KERNEL_DIR   = BASE_DIR / 'kernels'
WIMBOOT_DIR  = BASE_DIR / 'wimboot'
CONFIG_DIR   = BASE_DIR / 'config'
STATIC_DIR   = BASE_DIR / 'static'
CONFIG_FILE  = CONFIG_DIR / 'netventoy.json'
THEME_FILE   = CONFIG_DIR / 'theme.json'
GRUB_DIR     = TFTP_DIR  / 'grub'
GRUB_CFG     = GRUB_DIR  / 'grub.cfg'
DNSMASQ_CONF = CONFIG_DIR / 'dnsmasq.conf'

for _d in (ISO_DIR, TFTP_DIR, GRUB_DIR, KERNEL_DIR, WIMBOOT_DIR, CONFIG_DIR, STATIC_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ── Flask ────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path='/static')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 * 1024

# ── In-memory state ──────────────────────────────────────────────────────────
_lock                            = threading.Lock()
iso_db:      dict[str, dict]     = {}
job_status:  dict[str, dict]     = {}
dnsmasq_proc: subprocess.Popen | None = None

# ── Default theme ─────────────────────────────────────────────────────────────
DEFAULT_THEME = {
    'title':       'NetVentoy',
    'subtitle':    'Network Boot Server',
    'fg_normal':   '7',
    'bg_normal':   '0',
    'fg_selected': '0',
    'bg_selected': '2',
    'fg_hotkey':   '0',
    'bg_hotkey':   '6',
    'timeout':     30,
    'logo': (
        " _   _      _   _   _            _\n"
        "| \\ | | ___| |_| \\ | | ___  _ _| |_ ___  _   _\n"
        "|  \\| |/ _ \\ __|  \\| |/ _ \\| '_ \\ __/ _ \\| | | |\n"
        "| |\\  |  __/ |_| |\\  |  __/| | | | || (_) | |_| |\n"
        "|_| \\_|\\___|\\__|_| \\_|\\___|_| |_|\\__\\___/ \\__, |\n"
        "                                             |___/"
    ),
}

def load_theme() -> dict:
    if THEME_FILE.exists():
        try:
            return {**DEFAULT_THEME, **json.loads(THEME_FILE.read_text())}
        except Exception:
            pass
    return dict(DEFAULT_THEME)

def save_theme(t: dict) -> None:
    THEME_FILE.write_text(json.dumps(t, indent=2))

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_server_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'

def format_size(n: int) -> str:
    for u in ('B','KB','MB','GB','TB'):
        if n < 1024: return f'{n:.1f} {u}'
        n //= 1024
    return f'{n:.1f} PB'

def sanitize_label(s: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_]', '_', s)

def iso_key(path: Path) -> str:
    return path.relative_to(ISO_DIR).as_posix()

def new_job(jtype: str, name: str) -> str:
    jid = hashlib.md5(f'{jtype}{name}{time.time()}'.encode()).hexdigest()[:10]
    with _lock:
        job_status[jid] = {'id':jid,'type':jtype,'name':name,
                           'status':'running','progress':0,'message':'Starting...'}
    return jid

def finish_job(jid: str, ok: bool, msg: str) -> None:
    with _lock:
        if jid in job_status:
            job_status[jid].update({'status':'done' if ok else 'error',
                                    'progress':100 if ok else job_status[jid]['progress'],
                                    'message':msg})

# ── Distro detection ──────────────────────────────────────────────────────────
_DISTRO = [
    (['ubuntu','lubuntu','xubuntu','kubuntu','edubuntu'],
     'ubuntu', 'boot=casper quiet splash ---', '🟠'),
    (['linuxmint','mint'],
     'ubuntu', 'boot=casper quiet splash ---', '🍃'),
    (['debian'],
     'debian', 'boot=live quiet', '🔴'),
    (['kali'],
     'debian', 'boot=live components quiet splash', '🐉'),
    (['tails'],
     'debian', 'boot=live components nox11 quiet splash', '🔒'),
    (['fedora'],
     'redhat', 'root=live:CDLABEL=Fedora rd.live.image quiet', '🔵'),
    (['centos','rhel','rocky','almalinux','alma'],
     'redhat', 'root=live:CDLABEL= rd.live.image quiet', '🔵'),
    (['archlinux','arch'],
     'arch', 'archisobasedir=arch archisolabel=ARCH_', '🟣'),
    (['manjaro'],
     'arch', 'misobasedir=manjaro misolabel=MANJARO', '🟢'),
    (['opensuse','suse'],
     'opensuse', 'root=live:CDLABEL= rd.live.image quiet', '🦎'),
    (['alpine'],
     'alpine', 'alpine_dev=cdrom:iso9660 modules=loop,squashfs,sd-mod,usb-storage quiet', '⚪'),
    (['gentoo'],
     'gentoo', 'root=/dev/ram0 init=/linuxrc looptype=squashfs loop=/image.squashfs cdroot', '🧬'),
    (['memtest'],
     'tool', '', '🔧'),
    (['gparted','clonezilla','rescuezilla','systemrescue','hiren'],
     'tool', '', '🔧'),
    (['windows','win10','win11','winpe','w10','w11'],
     'windows', '', '🪟'),
]

_KERNEL_PATHS = {
    'ubuntu':   [('casper/vmlinuz','casper/initrd'),
                 ('casper/vmlinuz','casper/initrd.lz')],
    'debian':   [('live/vmlinuz','live/initrd.img'),
                 ('live/vmlinuz1','live/initrd1.img')],
    'redhat':   [('isolinux/vmlinuz','isolinux/initrd.img'),
                 ('images/pxeboot/vmlinuz','images/pxeboot/initrd.img')],
    'arch':     [('arch/boot/x86_64/vmlinuz-linux','arch/boot/x86_64/initramfs-linux.img')],
    'opensuse': [('boot/x86_64/loader/linux','boot/x86_64/loader/initrd')],
    'alpine':   [('boot/vmlinuz-lts','boot/initramfs-lts'),
                 ('boot/vmlinuz','boot/initramfs')],
    'gentoo':   [('isolinux/gentoo','isolinux/gentoo.igz')],
}

_GENERIC_KERNEL_PATHS = [
    ('isolinux/vmlinuz','isolinux/initrd.img'),
    ('live/vmlinuz','live/initrd.img'),
    ('casper/vmlinuz','casper/initrd'),
    ('boot/vmlinuz','boot/initrd.img'),
    ('boot/vmlinuz','boot/initramfs.img'),
]

_WINPE_FILES = [
    'sources/boot.wim', 'bootmgr', 'bootmgr.efi',
    'efi/boot/bootx64.efi', 'efi/microsoft/boot/bcd',
    'boot/bcd', 'boot/boot.sdi',
]

def detect_iso_type(path: Path) -> dict:
    name = path.stem.lower()
    for kws, t, args, icon in _DISTRO:
        if any(k in name for k in kws):
            return {'type':t, 'kernel_args':args, 'icon':icon}
    return {'type':'generic', 'kernel_args':'', 'icon':'💿'}

def scan_iso(path: Path) -> dict:
    key  = iso_key(path)
    old  = iso_db.get(key, {})
    stat = path.stat()
    det  = detect_iso_type(path)
    klbl = sanitize_label(key)
    return {
        'key':               key,
        'name':              old.get('name') or path.stem.replace('-',' ').replace('_',' ').title(),
        'filename':          path.name,
        'path':              key,
        'size':              stat.st_size,
        'size_human':        format_size(stat.st_size),
        'type':              det['type'],
        'icon':              old.get('icon', det['icon']),
        'kernel_args':       old.get('kernel_args', det['kernel_args']),
        'pinned':            old.get('pinned', False),
        'description':       old.get('description', ''),
        'enabled':           old.get('enabled', True),
        'mtime':             stat.st_mtime,
        'kernel_extracted':  (KERNEL_DIR/klbl/'vmlinuz').exists() and (KERNEL_DIR/klbl/'initrd').exists(),
        'wimboot_extracted': (WIMBOOT_DIR/klbl/'boot.wim').exists(),
    }

# ── Config ────────────────────────────────────────────────────────────────────
def load_config() -> None:
    global iso_db
    if CONFIG_FILE.exists():
        try:
            iso_db = json.loads(CONFIG_FILE.read_text()).get('isos', {})
            log.info('Config loaded (%d entries)', len(iso_db))
        except Exception as e:
            log.warning('Config load failed: %s', e); iso_db = {}

def save_config() -> None:
    CONFIG_FILE.write_text(json.dumps({'isos': iso_db}, indent=2))

def scan_all_isos() -> None:
    with _lock:
        found = set()
        for p in sorted(ISO_DIR.rglob('*.iso')):
            k = iso_key(p); found.add(k); iso_db[k] = scan_iso(p)
        for k in [k for k in iso_db if k not in found]:
            del iso_db[k]
        save_config()
    regenerate_grub_cfg()
    log.info('Scan complete — %d ISOs', len(iso_db))

# ── Extraction helpers ────────────────────────────────────────────────────────
def _extraction_tool() -> str | None:
    for t in ('xorriso', '7z', 'bsdtar'):
        if shutil.which(t): return t
    return None

def _extract_file(iso_path: Path, iso_file: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tool = _extraction_tool()

    if tool == 'xorriso':
        try:
            subprocess.run(
                ['xorriso', '-osirrox', 'on', '-indev', str(iso_path),
                 '-extract', iso_file, str(dest)],
                capture_output=True, timeout=120)
            if dest.exists(): return True
        except Exception as e:
            log.debug('xorriso extraction failed for %s: %s', iso_file, e)

    if tool == '7z':
        try:
            subprocess.run(
                ['7z', 'e', str(iso_path), iso_file, f'-o{dest.parent}', '-y'],
                capture_output=True, timeout=120)
            extracted = dest.parent / Path(iso_file).name
            if extracted.exists():
                if extracted != dest: extracted.rename(dest)
                return True
        except Exception as e:
            log.debug('7z extraction failed for %s: %s', iso_file, e)

    if tool == 'bsdtar':
        try:
            subprocess.run(
                ['bsdtar', '-xf', str(iso_path), '-C', str(dest.parent), iso_file],
                capture_output=True, timeout=120)
            extracted = dest.parent / iso_file
            if extracted.exists():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(extracted), str(dest))
                return True
        except Exception as e:
            log.debug('bsdtar extraction failed for %s: %s', iso_file, e)

    # Last resort: mount (needs root)
    if os.geteuid() == 0:
        mnt = Path(tempfile.mkdtemp(prefix='netventoy_'))
        try:
            subprocess.run(['mount','-o','loop,ro',str(iso_path),str(mnt)],
                           check=True, capture_output=True, timeout=30)
            src = mnt / iso_file
            if src.exists():
                shutil.copy2(str(src), str(dest))
                return dest.exists()
        except Exception as e:
            log.debug('mount extraction failed for %s: %s', iso_file, e)
        finally:
            subprocess.run(['umount', str(mnt)], capture_output=True, timeout=15)
            try: mnt.rmdir()
            except OSError: pass
    return False

# ── Kernel extraction ─────────────────────────────────────────────────────────
def extract_kernel(key: str, jid: str) -> None:
    with _lock: iso = iso_db.get(key)
    if not iso:
        finish_job(jid, False, 'ISO not found'); return

    iso_path = ISO_DIR / iso['path']
    klbl     = sanitize_label(key)
    kdir     = KERNEL_DIR / klbl
    kdir.mkdir(parents=True, exist_ok=True)

    candidates = _KERNEL_PATHS.get(iso['type'], []) + _GENERIC_KERNEL_PATHS
    vmlinuz    = kdir / 'vmlinuz'
    initrd     = kdir / 'initrd'
    success    = False

    for i, (ksrc, isrc) in enumerate(candidates):
        job_status[jid].update({'progress': int(10 + i*5), 'message': f'Trying {ksrc}...'})
        if _extract_file(iso_path, ksrc, vmlinuz):
            job_status[jid].update({'progress': 60, 'message': f'Kernel found, extracting initrd...'})
            # Try the paired initrd, then alternates
            for ia in [isrc, 'casper/initrd.lz', 'live/initrd1.img',
                       'isolinux/initrd', 'boot/initramfs.img', 'boot/initramfs']:
                if _extract_file(iso_path, ia, initrd):
                    success = True; break
        if success: break

    if success:
        (kdir/'meta.json').write_text(json.dumps({
            'iso_key': key, 'iso_type': iso['type'],
            'vmlinuz_size': vmlinuz.stat().st_size,
            'initrd_size':  initrd.stat().st_size,
            'extracted_at': time.time(),
        }, indent=2))
        with _lock:
            iso_db[key]['kernel_extracted'] = True
            save_config()
        regenerate_grub_cfg()
        finish_job(jid, True,
            f'Extracted kernel ({format_size(vmlinuz.stat().st_size)}) '
            f'+ initrd ({format_size(initrd.stat().st_size)})')
        log.info('Kernel extracted for %s', key)
    else:
        for f in (vmlinuz, initrd):
            if f.exists(): f.unlink()
        finish_job(jid, False,
            'Could not find kernel/initrd. '
            'Install xorriso (apt install xorriso) for best results, '
            'or verify this ISO contains a vmlinuz.')
        log.warning('Kernel extraction failed for %s', key)

# ── WinPE extraction ──────────────────────────────────────────────────────────
def extract_winpe(key: str, jid: str) -> None:
    with _lock: iso = iso_db.get(key)
    if not iso:
        finish_job(jid, False, 'ISO not found'); return

    iso_path = ISO_DIR / iso['path']
    klbl     = sanitize_label(key)
    wdir     = WIMBOOT_DIR / klbl
    wdir.mkdir(parents=True, exist_ok=True)
    extracted = 0

    for i, wf in enumerate(_WINPE_FILES):
        dest = wdir / Path(wf).name
        job_status[jid].update({
            'progress': int(5 + i/len(_WINPE_FILES)*80),
            'message':  f'Extracting {wf}...'
        })
        if _extract_file(iso_path, wf, dest):
            extracted += 1
            log.info('WinPE: extracted %s', wf)

    # Fetch wimboot binary if not present
    wimboot_bin = STATIC_DIR / 'wimboot'
    if not wimboot_bin.exists():
        job_status[jid].update({'progress': 88, 'message': 'Downloading wimboot binary...'})
        try:
            subprocess.run([
                'wget', '-q',
                'https://github.com/ipxe/wimboot/releases/latest/download/wimboot',
                '-O', str(wimboot_bin)
            ], timeout=60, check=True)
            wimboot_bin.chmod(0o755)
            log.info('wimboot binary downloaded')
        except Exception as e:
            log.warning('wimboot download failed: %s', e)

    if extracted > 0:
        (wdir/'meta.json').write_text(json.dumps({
            'iso_key': key, 'files': extracted, 'extracted_at': time.time()
        }, indent=2))
        with _lock:
            iso_db[key]['wimboot_extracted'] = True
            save_config()
        regenerate_grub_cfg()
        finish_job(jid, True, f'Extracted {extracted} WinPE files')
        log.info('WinPE extracted for %s (%d files)', key, extracted)
    else:
        finish_job(jid, False,
            'No WinPE files found. '
            'Install xorriso (apt install xorriso) and retry.')

# ── grub.cfg generation ───────────────────────────────────────────────────────
def regenerate_grub_cfg() -> None:
    """
    Generate tftp/grub/grub.cfg for both EFI and BIOS grub clients.

    Boot method priority per ISO (fastest / most Secure-Boot-friendly first):
      1. Direct kernel+initrd over HTTP  (kernel extracted, distro-signed kernels pass SB)
      2. loopback ISO                    (grub loopback + ISO loopback.cfg — no extraction needed)
      3. WinPE chainload via grub        (Windows only, wimboot extracted)

    Secure Boot warnings are emitted at menu selection time when the platform
    is EFI and Secure Boot is active and the boot method may not be SB-signed.
    """
    ip       = get_server_ip()
    base_url = f'http://{ip}:5000'
    t        = load_theme()
    timeout  = int(t['timeout'])
    title    = t['title']
    subtitle = t['subtitle']

    with _lock:
        enabled  = {k: v for k, v in iso_db.items() if v.get('enabled', True)}
        pinned   = [v for v in enabled.values() if v.get('pinned')]
        dir_map: dict[str, list] = {}
        for iso in enabled.values():
            parts = Path(iso['path']).parts
            d = '/'.join(parts[:-1]) if len(parts) > 1 else ''
            dir_map.setdefault(d, []).append(iso)

    pinned_keys = {i['key'] for i in pinned}

    L = [
        '# NetVentoy — generated grub.cfg',
        '# Do not edit by hand — regenerated automatically',
        '',
        '# ── Grub prefix: tell grub where to find modules ─────────────────',
        '# grubnetx64.efi.signed has modules built-in; this is for BIOS grub.',
        f'set prefix=(pxe)/grub',
        '',
        '# ── Platform & Secure Boot detection ─────────────────────────────',
        'set is_efi=false',
        'set secure_boot=false',
        'if [ "${grub_platform}" = "efi" ]; then',
        '  set is_efi=true',
        '  if [ "${grub_secureboot}" = "1" ]; then',
        '    set secure_boot=true',
        '  fi',
        'fi',
        '',
        '# ── Appearance ────────────────────────────────────────────────────',
        f'set menu_color_normal=white/black',
        f'set menu_color_highlight=black/green',
        f'set color_normal=white/black',
        f'set color_highlight=black/green',
        '',
        '# ── Timeout ───────────────────────────────────────────────────────',
        f'set timeout={timeout}',
        'set timeout_style=menu',
        '',
        '# ── Helper: Secure Boot warning ───────────────────────────────────',
        '# Called before booting an unsigned/unverifiable image on EFI+SB.',
        'function sb_warn {',
        '  if [ "${secure_boot}" = "true" ]; then',
        '    echo ""',
        '    echo "  !! Secure Boot WARNING !!"',
        '    echo "  This image may not be Secure Boot signed."',
        '    echo "  Boot may fail if firmware enforcement is strict."',
        '    echo "  Press ENTER to continue or wait 10 seconds..."',
        '    echo ""',
        '    sleep 10',
        '  fi',
        '}',
        '',
    ]

    # ── Main menu ──────────────────────────────────────────────────────────
    L += [
        f'menuentry "{title}  --  {subtitle}" --class header {{ true }}',
        '',
    ]

    # Pinned entries at the top level
    if pinned:
        L.append('# ── Pinned ────────────────────────────────────────────────────────')
        for iso in pinned:
            _grub_entry(L, iso, base_url, indent='')
        L.append('')

    # Root-level ISOs
    root_isos = [i for i in dir_map.get('', []) if i['key'] not in pinned_keys]
    if root_isos:
        L.append('# ── Images ────────────────────────────────────────────────────────')
        for iso in root_isos:
            _grub_entry(L, iso, base_url, indent='')
        L.append('')

    # Sub-directories as grub submenus
    for d in sorted(k for k in dir_map if k):
        isos_in = dir_map[d]
        L.append(f'submenu "  {d}/" {{')
        for iso in isos_in:
            _grub_entry(L, iso, base_url, indent='  ')
        L += ['}', '']

    # Utilities always available
    L += [
        '# ── Utilities ─────────────────────────────────────────────────────',
        'menuentry "Reboot" {',
        '  reboot',
        '}',
        'menuentry "Shutdown" {',
        '  halt',
        '}',
        'if [ "${is_efi}" = "true" ]; then',
        '  menuentry "EFI Firmware Setup" {',
        '    fwsetup',
        '  }',
        'fi',
    ]

    GRUB_CFG.write_text('\n'.join(L))
    log.info('grub.cfg written (%d entries)', len(enabled))


def _grub_entry(L: list, iso: dict, base_url: str, indent: str) -> None:
    """Append a single grub menuentry for an ISO, choosing the best boot method."""
    name  = iso['name'].replace('"', "'")
    icon  = iso['icon']
    klbl  = sanitize_label(iso['key'])
    kargs = iso.get('kernel_args', '').strip()

    label = f'{icon}  {name}'

    if iso['type'] == 'windows':
        _grub_entry_windows(L, iso, label, klbl, base_url, indent)
        return

    if iso.get('kernel_extracted'):
        # ── Method 1: direct kernel+initrd (fastest, SB-compatible if kernel signed)
        kern_url = f'{base_url}/kernels/{klbl}/vmlinuz'
        idr_url  = f'{base_url}/kernels/{klbl}/initrd'
        sb_note  = '# kernel may be distro-signed — SB compatible for major distros'
        L += [
            f'{indent}menuentry "{label}" {{',
            f'{indent}  # Boot method: direct kernel+initrd (HTTP)',
            f'{indent}  {sb_note}',
            f'{indent}  echo "Loading {name}..."',
            f'{indent}  linux  (http,{base_url.split("//")[1]})/kernels/{klbl}/vmlinuz {kargs}',
            f'{indent}  initrd (http,{base_url.split("//")[1]})/kernels/{klbl}/initrd',
            f'{indent}}}',
            '',
        ]
    else:
        # ── Method 2: grub loopback from ISO (no extraction needed)
        # grub loads the ISO over HTTP, mounts it, and runs the ISO's own loopback.cfg
        # This requires the ISO to contain /boot/grub/loopback.cfg (most modern distros do)
        iso_http = f'(http,{base_url.split("//")[1]})/isos/{iso["path"]}'
        L += [
            f'{indent}menuentry "{label}" {{',
            f'{indent}  # Boot method: grub loopback ISO (HTTP)',
            f'{indent}  # Note: requires ISO to contain /boot/grub/loopback.cfg',
            f'{indent}  # Secure Boot: depends on kernels inside the ISO',
            f'{indent}  if [ "${{secure_boot}}" = "true" ]; then',
            f'{indent}    sb_warn',
            f'{indent}  fi',
            f'{indent}  echo "Loading {name}..."',
            f'{indent}  set iso_path=/isos/{iso["path"]}',
            f'{indent}  loopback loop {iso_http}',
            f'{indent}  set root=(loop)',
            f'{indent}  configfile /boot/grub/loopback.cfg',
            f'{indent}}}',
            '',
        ]


def _grub_entry_windows(L: list, iso: dict, label: str, klbl: str,
                         base_url: str, indent: str) -> None:
    """Windows entry — chainload grub to wimboot via linux16 shim."""
    wdir = WIMBOOT_DIR / klbl

    if iso.get('wimboot_extracted') and wdir.exists():
        # grub hands off to wimboot which loads WinPE
        # wimboot is served as a plain binary over HTTP
        host = base_url.split('//')[1]
        L += [
            f'{indent}menuentry "{label}" {{',
            f'{indent}  # Boot method: wimboot (Windows PE)',
            f'{indent}  # Secure Boot: wimboot is not MS-signed; SB must be disabled or key enrolled',
            f'{indent}  if [ "${{secure_boot}}" = "true" ]; then',
            f'{indent}    sb_warn',
            f'{indent}  fi',
            f'{indent}  echo "Loading Windows PE..."',
            f'{indent}  if [ "${{is_efi}}" = "true" ]; then',
            f'{indent}    linuxefi (http,{host})/static/wimboot',
        ]
        for fname, wlabel in [('bootmgr','bootmgr'), ('boot.sdi','boot.sdi'),
                               ('bcd','BCD'), ('boot.wim','boot.wim')]:
            if (wdir / fname).exists():
                L.append(f'{indent}    initrdefi (http,{host})/wimboot/{klbl}/{fname} {wlabel}')
        L += [
            f'{indent}  else',
            f'{indent}    linux16 (http,{host})/static/wimboot',
        ]
        for fname, wlabel in [('bootmgr','bootmgr'), ('boot.sdi','boot.sdi'),
                               ('bcd','BCD'), ('boot.wim','boot.wim')]:
            if (wdir / fname).exists():
                L.append(f'{indent}    initrd16 (http,{host})/wimboot/{klbl}/{fname} {wlabel}')
        L += [
            f'{indent}  fi',
            f'{indent}}}',
            '',
        ]
    else:
        L += [
            f'{indent}menuentry "{label}" {{',
            f'{indent}  echo "Windows PE not yet extracted."',
            f'{indent}  echo "Use the NetVentoy web UI to run Extract WinPE on this ISO."',
            f'{indent}  sleep 5',
            f'{indent}}}',
            '',
        ]


# ── dnsmasq ───────────────────────────────────────────────────────────────────
def _detect_iface() -> str:
    try:
        words = subprocess.check_output(['ip','route','get','1.1.1.1'],text=True).split()
        return words[words.index('dev')+1]
    except Exception: return 'eth0'


def write_dnsmasq_conf(iface: str = '') -> str:
    """
    ProxyDHCP-only dnsmasq config.

    Architecture detection uses DHCP option 93 (client-arch):
      0  = x86 BIOS
      6  = x86 UEFI (32-bit, rare)
      7  = x86_64 UEFI
      9  = x86_64 UEFI (alternate)
      10 = 32-bit EFI BC (rare)

    BIOS clients   → grub BIOS PXE binary over TFTP
    EFI clients    → shimx64.efi over TFTP
    HTTP Boot      → shimx64.efi served over HTTP (parallel, same shim)

    The USG has NO PXE options set — dnsmasq ProxyDHCP is the sole PXE authority.
    """
    ip    = get_server_ip()
    iface = iface or _detect_iface()

    # Paths of grub BIOS PXE binary — generated by grub-mknetdir during setup
    grub_bios_bin = 'grub/i386-pc/core.0'

    conf = '\n'.join([
        '# NetVentoy — dnsmasq ProxyDHCP configuration',
        '# Handles PXE boot only. IP assignment is left entirely to the router.',
        '# USG must have NO PXE/next-server options configured.',
        '',
        '# Disable dnsmasq DNS server — we are PXE-only',
        'port=0',
        f'interface={iface}',
        'bind-interfaces',
        '',
        '# ProxyDHCP: respond to PXE clients on our subnet without assigning IPs',
        f'dhcp-range={ip},proxy',
        'dhcp-no-override',
        'log-dhcp',
        '',
        '# ── Architecture detection ─────────────────────────────────────────',
        '# Tag EFI clients (option 93 values 6, 7, 9 = x86 EFI variants)',
        'dhcp-match=set:efi-x86_64,option:client-arch,7',
        'dhcp-match=set:efi-x86_64,option:client-arch,9',
        'dhcp-match=set:efi-x86,option:client-arch,6',
        '# BIOS = anything not tagged as EFI',
        '',
        '# ── TFTP boot files ────────────────────────────────────────────────',
        '# EFI: shim first (Microsoft-trusted), shim chainloads signed grubx64.efi',
        f'dhcp-boot=tag:efi-x86_64,shimx64.efi,,{ip}',
        f'dhcp-boot=tag:efi-x86,shimia32.efi,,{ip}',
        '# BIOS: grub BIOS core image (generated by grub-mknetdir)',
        f'dhcp-boot=tag:!efi-x86_64,tag:!efi-x86,{grub_bios_bin},,{ip}',
        '',
        '# ── HTTP Boot (UEFI 2.5+ clients, parallel with TFTP) ─────────────',
        '# Clients that support HTTP Boot will prefer this URL over TFTP.',
        '# vendor-class HTTPClient identifies HTTP Boot capable firmware.',
        f'dhcp-match=set:httpboot,option:vendor-class,HTTPClient',
        f'dhcp-boot=tag:httpboot,tag:efi-x86_64,http://{ip}:5000/tftp/shimx64.efi',
        '',
        '# ── TFTP server ────────────────────────────────────────────────────',
        'enable-tftp',
        f'tftp-root={TFTP_DIR}',
        '',
    ])

    DNSMASQ_CONF.write_text(conf)
    return conf

def _kill_stale_dnsmasq() -> None:
    """Kill any dnsmasq processes left over from previous runs."""
    try:
        out = subprocess.check_output(['pgrep', '-a', 'dnsmasq'], text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return  # no dnsmasq running
    for line in out.splitlines():
        pid_str = line.split()[0]
        try:
            pid = int(pid_str)
            os.kill(pid, signal.SIGTERM)
            log.info('killed stale dnsmasq PID %d', pid)
        except (ValueError, ProcessLookupError, PermissionError):
            pass
    # give them a moment to exit
    time.sleep(0.5)


def start_dnsmasq(iface: str = '') -> bool:
    global dnsmasq_proc
    if dnsmasq_proc and dnsmasq_proc.poll() is None: return True
    if not shutil.which('dnsmasq'):
        log.warning('dnsmasq not found — apt install dnsmasq'); return False
    # Kill any orphaned dnsmasq processes before starting fresh
    _kill_stale_dnsmasq()
    write_dnsmasq_conf(iface)
    try:
        dnsmasq_proc = subprocess.Popen(
            ['dnsmasq','--no-daemon',f'--conf-file={DNSMASQ_CONF}','--log-facility=-'],
            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
        log.info('dnsmasq started (PID %d)', dnsmasq_proc.pid)
        # Start a background thread to relay dnsmasq log output
        threading.Thread(target=_relay_dnsmasq_logs, daemon=True).start()
        return True
    except PermissionError:
        log.error('dnsmasq: permission denied — run as root'); return False
    except Exception as e:
        log.error('dnsmasq failed: %s', e); return False


def _relay_dnsmasq_logs() -> None:
    """Read dnsmasq stderr (--log-facility=-) and forward to our logger."""
    if not dnsmasq_proc or not dnsmasq_proc.stderr:
        return
    for line in dnsmasq_proc.stderr:
        text = line.decode('utf-8', errors='replace').rstrip()
        if text:
            log.info('[dnsmasq] %s', text)


def stop_dnsmasq() -> None:
    global dnsmasq_proc
    if dnsmasq_proc:
        dnsmasq_proc.terminate()
        try: dnsmasq_proc.wait(timeout=5)
        except subprocess.TimeoutExpired: dnsmasq_proc.kill()
        dnsmasq_proc = None
        log.info('dnsmasq stopped')
    # Also clean up any orphaned instances
    _kill_stale_dnsmasq()

def dnsmasq_running() -> bool:
    return dnsmasq_proc is not None and dnsmasq_proc.poll() is None

# ── Watchdog ──────────────────────────────────────────────────────────────────
class ISOChangeHandler(FileSystemEventHandler):
    _timer: threading.Timer | None = None
    _debounce = 1.2

    def _schedule(self):
        if self._timer: self._timer.cancel()
        self._timer = threading.Timer(self._debounce, scan_all_isos)
        self._timer.daemon = True; self._timer.start()

    def on_created(self, e):
        if not e.is_directory and e.src_path.endswith('.iso'):
            log.info('inotify: new ISO %s', e.src_path); self._schedule()
    def on_deleted(self, e):
        if not e.is_directory and e.src_path.endswith('.iso'):
            log.info('inotify: deleted %s', e.src_path); self._schedule()
    def on_moved(self, e):
        if not e.is_directory and (e.src_path.endswith('.iso') or e.dest_path.endswith('.iso')):
            log.info('inotify: moved %s', e.dest_path); self._schedule()
    def on_closed(self, e):
        if not e.is_directory and e.src_path.endswith('.iso'):
            log.info('inotify: write closed %s', e.src_path); self._schedule()

def start_watcher() -> Observer:
    obs = Observer()
    obs.schedule(ISOChangeHandler(), str(ISO_DIR), recursive=True)
    obs.daemon = True; obs.start()
    log.info('inotify watcher on %s', ISO_DIR)
    return obs

# ── Routes — ISO ──────────────────────────────────────────────────────────────
@app.route('/api/isos')
def api_isos():
    with _lock: return jsonify(list(iso_db.values()))

@app.route('/api/iso/<path:key>', methods=['GET'])
def api_iso_get(key):
    with _lock: iso = iso_db.get(key)
    return jsonify(iso) if iso else (jsonify({'error':'Not found'}), HTTPStatus.NOT_FOUND)

@app.route('/api/iso/<path:key>', methods=['PATCH'])
def api_iso_update(key):
    with _lock:
        iso = iso_db.get(key)
        if not iso: return jsonify({'error':'Not found'}), HTTPStatus.NOT_FOUND
        data = request.get_json(force=True) or {}
        for f in ('name','description','pinned','enabled','kernel_args','icon'):
            if f in data: iso[f] = data[f]
        iso_db[key] = iso; save_config()
    regenerate_grub_cfg()
    return jsonify(iso)

@app.route('/api/iso/<path:key>', methods=['DELETE'])
def api_iso_delete(key):
    with _lock:
        iso = iso_db.get(key)
        if not iso: return jsonify({'error':'Not found'}), HTTPStatus.NOT_FOUND
        p = ISO_DIR / iso['path']
        if p.exists(): p.unlink()
        klbl = sanitize_label(key)
        for d in (KERNEL_DIR/klbl, WIMBOOT_DIR/klbl):
            if d.exists(): shutil.rmtree(d)
        del iso_db[key]; save_config()
    regenerate_grub_cfg()
    return jsonify({'ok': True})

@app.route('/api/iso/<path:key>/move', methods=['POST'])
def api_iso_move(key):
    with _lock:
        iso = iso_db.get(key)
        if not iso: return jsonify({'error':'Not found'}), HTTPStatus.NOT_FOUND
    data    = request.get_json(force=True) or {}
    new_dir = data.get('directory','').strip('/')
    new_abs = (ISO_DIR/new_dir if new_dir else ISO_DIR)
    new_abs.mkdir(parents=True, exist_ok=True)
    shutil.move(str(ISO_DIR/iso['path']), str(new_abs/iso['filename']))
    return jsonify({'ok': True})

@app.route('/api/iso/<path:key>/extract_kernel', methods=['POST'])
def api_extract_kernel(key):
    with _lock: iso = iso_db.get(key)
    if not iso: return jsonify({'error':'Not found'}), HTTPStatus.NOT_FOUND
    if iso['type'] == 'windows':
        return jsonify({'error':'Use /extract_winpe for Windows'}), HTTPStatus.BAD_REQUEST
    jid = new_job('extract_kernel', iso['name'])
    threading.Thread(target=extract_kernel, args=(key,jid), daemon=True).start()
    return jsonify({'ok':True, 'job_id':jid})

@app.route('/api/iso/<path:key>/extract_winpe', methods=['POST'])
def api_extract_winpe(key):
    with _lock: iso = iso_db.get(key)
    if not iso: return jsonify({'error':'Not found'}), HTTPStatus.NOT_FOUND
    jid = new_job('extract_winpe', iso['name'])
    threading.Thread(target=extract_winpe, args=(key,jid), daemon=True).start()
    return jsonify({'ok':True, 'job_id':jid})

@app.route('/api/iso/<path:key>/clear_extraction', methods=['POST'])
def api_clear_extraction(key):
    with _lock:
        iso = iso_db.get(key)
        if not iso: return jsonify({'error':'Not found'}), HTTPStatus.NOT_FOUND
        klbl = sanitize_label(key)
        for d in (KERNEL_DIR/klbl, WIMBOOT_DIR/klbl):
            if d.exists(): shutil.rmtree(d)
        iso['kernel_extracted'] = False
        iso['wimboot_extracted'] = False
        save_config()
    regenerate_grub_cfg()
    return jsonify({'ok': True})

# ── Routes — jobs, upload, misc ───────────────────────────────────────────────
@app.route('/api/job/<jid>')
def api_job(jid):
    with _lock: j = job_status.get(jid)
    return jsonify(j) if j else (jsonify({'error':'Unknown job'}), HTTPStatus.NOT_FOUND)

@app.route('/api/jobs')
def api_jobs():
    with _lock:
        jobs = sorted(job_status.values(), key=lambda j:j['id'], reverse=True)[:20]
    return jsonify(jobs)

@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'error':'No file'}), HTTPStatus.BAD_REQUEST
    f        = request.files['file']
    directory = request.form.get('directory','').strip('/')
    filename  = secure_filename(f.filename or '')
    if not filename or not filename.lower().endswith('.iso'):
        return jsonify({'error':'Only .iso files accepted'}), HTTPStatus.BAD_REQUEST
    dest_dir = ISO_DIR/directory if directory else ISO_DIR
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / filename
    try: f.save(str(dest))
    except Exception as e: return jsonify({'error':str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
    scan_all_isos()
    with _lock: iso = iso_db.get(iso_key(dest), {})
    return jsonify({'ok':True, 'key':iso_key(dest), 'iso':iso})

@app.route('/api/directories')
def api_directories():
    dirs = set()
    with _lock:
        for k in iso_db:
            parts = Path(k).parts
            for i in range(len(parts)-1): dirs.add('/'.join(parts[:i+1]))
    return jsonify(sorted(dirs))

@app.route('/api/mkdir', methods=['POST'])
def api_mkdir():
    data = request.get_json(force=True) or {}
    d = data.get('directory','').strip('/')
    if not d: return jsonify({'error':'directory required'}), HTTPStatus.BAD_REQUEST
    (ISO_DIR/d).mkdir(parents=True, exist_ok=True)
    return jsonify({'ok': True})

@app.route('/api/status')
def api_status():
    with _lock:
        count = len(iso_db)
        kern  = sum(1 for v in iso_db.values() if v.get('kernel_extracted'))
        win   = sum(1 for v in iso_db.values() if v.get('wimboot_extracted'))
    shim_ok  = (TFTP_DIR / 'shimx64.efi').exists()
    grub_ok  = (TFTP_DIR / 'grubx64.efi').exists()
    bios_ok  = (TFTP_DIR / 'grub' / 'i386-pc' / 'core.0').exists()
    return jsonify({
        'server_ip':         get_server_ip(),
        'iso_count':         count,
        'kernels_extracted': kern,
        'winpe_extracted':   win,
        'dnsmasq_running':   dnsmasq_running(),
        'shim_present':      shim_ok,
        'grub_efi_present':  grub_ok,
        'grub_bios_present': bios_ok,
        'iso_dir':           str(ISO_DIR),
        'tftp_dir':          str(TFTP_DIR),
        'extraction_tool':   _extraction_tool() or 'none — apt install xorriso',
    })

@app.route('/api/dnsmasq/start', methods=['POST'])
def api_dnsmasq_start():
    data = request.get_json(force=True) or {}
    ok   = start_dnsmasq(data.get('interface',''))
    return jsonify({'ok':ok, 'running':dnsmasq_running()})

@app.route('/api/dnsmasq/stop', methods=['POST'])
def api_dnsmasq_stop():
    stop_dnsmasq(); return jsonify({'ok':True,'running':False})

@app.route('/api/rescan', methods=['POST'])
def api_rescan():
    scan_all_isos()
    with _lock: count = len(iso_db)
    return jsonify({'ok':True, 'count':count})

# ── Routes — theme ────────────────────────────────────────────────────────────
@app.route('/api/theme', methods=['GET'])
def api_theme_get(): return jsonify(load_theme())

@app.route('/api/theme', methods=['POST'])
def api_theme_set():
    data = request.get_json(force=True) or {}
    t    = load_theme()
    for k in ('title','subtitle','fg_normal','bg_normal','fg_selected',
              'bg_selected','fg_hotkey','bg_hotkey','timeout','logo'):
        if k in data: t[k] = data[k]
    save_theme(t); regenerate_grub_cfg()
    return jsonify(t)

@app.route('/api/theme/reset', methods=['POST'])
def api_theme_reset():
    save_theme(DEFAULT_THEME); regenerate_grub_cfg()
    return jsonify(DEFAULT_THEME)

# ── Routes — file serving ─────────────────────────────────────────────────────
@app.route('/api/config/dnsmasq')
def api_dnsmasq_conf():
    return Response(DNSMASQ_CONF.read_text() if DNSMASQ_CONF.exists() else '# Not generated\n',
                    mimetype='text/plain')

@app.route('/api/menu/preview')
def api_menu_preview():
    return Response(GRUB_CFG.read_text() if GRUB_CFG.exists() else '# grub.cfg not yet generated\n',
                    mimetype='text/plain')

@app.route('/')
def index():
    with _lock:
        isos   = list(iso_db.values())
        pinned = [i for i in isos if i.get('pinned')]
    return render_template('index.html', isos=isos, pinned=pinned,
                           server_ip=get_server_ip(), dnsmasq_running=dnsmasq_running())

@app.route('/grub/grub.cfg')
def serve_grub_cfg():
    """Serve grub.cfg to grub clients loading over HTTP or TFTP-proxied HTTP."""
    content = GRUB_CFG.read_text() if GRUB_CFG.exists() else '# empty\n'
    return Response(content, mimetype='text/plain')

@app.route('/tftp/<path:filename>')
def serve_tftp_over_http(filename: str):
    """
    Serve TFTP files over HTTP for UEFI HTTP Boot clients.
    HTTP Boot firmware fetches shimx64.efi and subsequent files via HTTP
    using the same base URL.  This route makes the TFTP directory
    accessible at http://SERVER:5000/tftp/.
    """
    return send_from_directory(TFTP_DIR, filename, conditional=True)

@app.route('/isos/<path:filename>')
def serve_iso(filename): return send_from_directory(ISO_DIR, filename, conditional=True)

@app.route('/kernels/<path:filename>')
def serve_kernel(filename): return send_from_directory(KERNEL_DIR, filename, conditional=True)

@app.route('/wimboot/<path:filename>')
def serve_wimboot(filename): return send_from_directory(WIMBOOT_DIR, filename, conditional=True)

# ── Startup / shutdown ────────────────────────────────────────────────────────
_watcher: Observer | None = None

def startup():
    global _watcher
    load_config(); scan_all_isos()
    _watcher = start_watcher()
    start_dnsmasq()

def shutdown(sig, frame):
    log.info('Shutting down...')
    stop_dnsmasq()
    if _watcher: _watcher.stop(); _watcher.join(timeout=3)
    sys.exit(0)

signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)

if __name__ == '__main__':
    print(r"""
  _   _      _   _   _            _
 | \ | | ___| |_| \ | | ___  _ _| |_ ___  _   _
 |  \| |/ _ \ __|  \| |/ _ \| '_ \ __/ _ \| | | |
 | |\  |  __/ |_| |\  |  __/| | | | || (_) | |_| |
 |_| \_|\___|\__|_| \_|\___||_| |_|\__\___/ \__, |
                                              |___/
  Ventoy for the Network Age  —  Debian 13 Edition
""")
    startup()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
