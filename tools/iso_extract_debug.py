#!/usr/bin/env python3
"""Standalone ISO kernel extraction debugger for netventoy.

Usage:
    python3 tools/iso_extract_debug.py <path-to-iso> [--extract <output-dir>]

This tool helps diagnose why kernel extraction fails by:
  1. Detecting available extraction tools (xorriso, 7z, bsdtar)
  2. Listing all files inside the ISO
  3. Searching for kernel/initrd candidates
  4. Attempting extraction of each candidate with verbose output
  5. Optionally extracting found kernel+initrd to an output directory
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ── Same kernel path tables as app.py ────────────────────────────────────────

KERNEL_PATHS = {
    'ubuntu':   [('casper/vmlinuz','casper/initrd'),
                 ('casper/vmlinuz','casper/initrd.lz')],
    'debian':   [('live/vmlinuz','live/initrd.img'),
                 ('live/vmlinuz1','live/initrd1.img'),
                 ('install.amd/vmlinuz','install.amd/initrd.gz'),
                 ('install.amd/vmlinuz','install.amd/gtk/initrd.gz'),
                 ('install.386/vmlinuz','install.386/initrd.gz'),
                 ('install.arm64/vmlinuz','install.arm64/initrd.gz'),
                 ('d-i/vmlinuz','d-i/initrd.gz')],
    'redhat':   [('isolinux/vmlinuz','isolinux/initrd.img'),
                 ('images/pxeboot/vmlinuz','images/pxeboot/initrd.img')],
    'arch':     [('arch/boot/x86_64/vmlinuz-linux','arch/boot/x86_64/initramfs-linux.img')],
    'opensuse': [('boot/x86_64/loader/linux','boot/x86_64/loader/initrd')],
    'alpine':   [('boot/vmlinuz-lts','boot/initramfs-lts'),
                 ('boot/vmlinuz','boot/initramfs')],
    'gentoo':   [('isolinux/gentoo','isolinux/gentoo.igz')],
}

GENERIC_KERNEL_PATHS = [
    ('isolinux/vmlinuz','isolinux/initrd.img'),
    ('live/vmlinuz','live/initrd.img'),
    ('casper/vmlinuz','casper/initrd'),
    ('boot/vmlinuz','boot/initrd.img'),
    ('boot/vmlinuz','boot/initramfs.img'),
    ('install.amd/vmlinuz','install.amd/initrd.gz'),
    ('install.386/vmlinuz','install.386/initrd.gz'),
]

# Patterns that look like kernels or initrds
KERNEL_PATTERNS = re.compile(
    r'(vmlinuz|bzImage|linux|gentoo)$', re.IGNORECASE)
INITRD_PATTERNS = re.compile(
    r'(initrd|initramfs|gentoo\.igz)(\.img|\.gz|\.lz|\.xz|\.zst)?$', re.IGNORECASE)


def header(msg: str) -> None:
    print(f'\n{"="*60}')
    print(f'  {msg}')
    print(f'{"="*60}')


def check_tools() -> dict[str, str | None]:
    """Check which extraction tools are available."""
    header('Checking extraction tools')
    tools = {}
    for name in ('xorriso', '7z', 'bsdtar', 'mount', 'isoinfo'):
        path = shutil.which(name)
        status = f'FOUND at {path}' if path else 'NOT FOUND'
        print(f'  {name:12s} {status}')
        tools[name] = path
    return tools


def list_iso_xorriso(iso_path: str) -> list[str]:
    """List all files in ISO using xorriso."""
    try:
        r = subprocess.run(
            ['xorriso', '-osirrox', 'on', '-indev', iso_path,
             '-find', '/', '-type', 'f', '-exec', 'report_lba', '--'],
            capture_output=True, text=True, timeout=60)
        files = []
        for line in r.stdout.splitlines():
            # xorriso report_lba output format:
            # File ... : ...  content  lba=... , size=... , ... path='...'
            if "path='" in line:
                path = line.split("path='")[1].rstrip("'")
                files.append(path)
            elif line.startswith('Report layout:') or line.startswith('File '):
                continue
        # Fallback: try simpler listing if report_lba gave nothing
        if not files:
            r2 = subprocess.run(
                ['xorriso', '-osirrox', 'on', '-indev', iso_path,
                 '-find', '/', '-type', 'f'],
                capture_output=True, text=True, timeout=60)
            for line in r2.stdout.splitlines():
                line = line.strip()
                if line.startswith('/'):
                    files.append(line)
            if r2.stderr:
                print(f'  xorriso stderr:\n{indent(r2.stderr)}')
        return files
    except Exception as e:
        print(f'  xorriso listing failed: {e}')
        return []


def list_iso_7z(iso_path: str) -> list[str]:
    """List all files in ISO using 7z."""
    try:
        r = subprocess.run(
            ['7z', 'l', '-slt', iso_path],
            capture_output=True, text=True, timeout=60)
        files = []
        for line in r.stdout.splitlines():
            if line.startswith('Path = ') and '.' in line:
                p = line[7:]
                if '/' in p or '.' in p:
                    files.append('/' + p)
        return files
    except Exception as e:
        print(f'  7z listing failed: {e}')
        return []


def list_iso_bsdtar(iso_path: str) -> list[str]:
    """List all files in ISO using bsdtar."""
    try:
        r = subprocess.run(
            ['bsdtar', '-tf', iso_path],
            capture_output=True, text=True, timeout=60)
        return ['/' + l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception as e:
        print(f'  bsdtar listing failed: {e}')
        return []


def list_iso_isoinfo(iso_path: str) -> list[str]:
    """List files using isoinfo (genisoimage)."""
    try:
        r = subprocess.run(
            ['isoinfo', '-J', '-l', '-i', iso_path],
            capture_output=True, text=True, timeout=60)
        files = []
        current_dir = '/'
        for line in r.stdout.splitlines():
            if line.startswith('Directory listing of '):
                current_dir = line.split('Directory listing of ')[1].strip()
            elif line.strip() and not line.startswith('d') and ']' in line:
                # Parse isoinfo file listing
                parts = line.strip().split()
                if parts:
                    fname = parts[-1]
                    if fname not in ('.', '..'):
                        files.append(current_dir + fname)
        # Also try Rock Ridge extensions
        if not files:
            r2 = subprocess.run(
                ['isoinfo', '-R', '-l', '-i', iso_path],
                capture_output=True, text=True, timeout=60)
            for line in r2.stdout.splitlines():
                if line.startswith('Directory listing of '):
                    current_dir = line.split('Directory listing of ')[1].strip()
                elif line.strip() and not line.startswith('d') and not line.startswith('total'):
                    parts = line.strip().split()
                    if len(parts) >= 8:
                        fname = parts[-1]
                        if fname not in ('.', '..'):
                            files.append(current_dir + fname)
        return files
    except Exception as e:
        print(f'  isoinfo listing failed: {e}')
        return []


def indent(text: str, prefix: str = '    ') -> str:
    return '\n'.join(prefix + line for line in text.splitlines())


def list_iso_files(iso_path: str, tools: dict) -> list[str]:
    """List all files in the ISO using the best available tool."""
    header('Listing ISO contents')

    files: list[str] = []
    for tool_name, list_fn in [
        ('xorriso', list_iso_xorriso),
        ('7z',      list_iso_7z),
        ('bsdtar',  list_iso_bsdtar),
        ('isoinfo', list_iso_isoinfo),
    ]:
        if tools.get(tool_name):
            print(f'\n  Using {tool_name} to list files...')
            files = list_fn(iso_path)
            if files:
                print(f'  Found {len(files)} files')
                break
            else:
                print(f'  {tool_name} returned no files, trying next tool...')

    if not files:
        print('  ERROR: Could not list ISO contents with any tool!')
        return []

    return files


def find_kernel_candidates(files: list[str]) -> tuple[list[str], list[str]]:
    """Search file listing for anything that looks like a kernel or initrd."""
    header('Searching for kernel/initrd candidates in file listing')

    kernels = []
    initrds = []

    for f in files:
        basename = f.rstrip('/').rsplit('/', 1)[-1]
        if KERNEL_PATTERNS.search(basename):
            kernels.append(f)
        if INITRD_PATTERNS.search(basename):
            initrds.append(f)

    if kernels:
        print(f'\n  Kernel candidates found ({len(kernels)}):')
        for k in kernels:
            print(f'    {k}')
    else:
        print('\n  WARNING: No kernel candidates found in file listing!')

    if initrds:
        print(f'\n  Initrd candidates found ({len(initrds)}):')
        for i in initrds:
            print(f'    {i}')
    else:
        print('\n  WARNING: No initrd candidates found in file listing!')

    return kernels, initrds


def detect_iso_type(iso_path: str) -> str:
    """Detect ISO type from filename (same logic as app.py)."""
    name = Path(iso_path).stem.lower()
    distros = [
        (['ubuntu','kubuntu','xubuntu','lubuntu','edubuntu','budgie','mate-desktop'],
         'ubuntu'),
        (['debian','devuan'], 'debian'),
        (['fedora','centos','rocky','alma','rhel','oracle-linux'], 'redhat'),
        (['arch','archlinux','endeavouros','manjaro','garuda'], 'arch'),
        (['opensuse','suse','leap','tumbleweed'], 'opensuse'),
        (['alpine'], 'alpine'),
        (['gentoo'], 'gentoo'),
        (['nixos'], 'generic'),
        (['kali','parrot','tails'], 'debian'),
        (['proxmox'], 'debian'),
        (['freebsd','openbsd','netbsd'], 'generic'),
        (['gparted','clonezilla','rescuezilla','systemrescue','hiren'], 'generic'),
        (['windows','win10','win11','winpe','w10','w11'], 'windows'),
    ]
    for kws, t in distros:
        if any(k in name for k in kws):
            return t
    return 'generic'


def try_extract_xorriso(iso_path: str, iso_file: str, dest: str) -> bool:
    """Try extracting a file with xorriso, with full debug output."""
    # xorriso expects paths with leading /
    if not iso_file.startswith('/'):
        iso_file_arg = '/' + iso_file
    else:
        iso_file_arg = iso_file

    print(f'\n    xorriso -osirrox on -indev {iso_path} '
          f'-extract {iso_file_arg} {dest}')
    try:
        r = subprocess.run(
            ['xorriso', '-osirrox', 'on', '-indev', iso_path,
             '-extract', iso_file_arg, str(dest)],
            capture_output=True, text=True, timeout=120)
        if r.stdout.strip():
            print(f'    stdout: {r.stdout.strip()[:200]}')
        if r.stderr.strip():
            print(f'    stderr: {r.stderr.strip()[:500]}')
        print(f'    return code: {r.returncode}')
        exists = Path(dest).exists()
        if exists:
            size = Path(dest).stat().st_size
            print(f'    SUCCESS: extracted {size:,} bytes')
        else:
            print(f'    FAILED: destination file does not exist')
        return exists
    except Exception as e:
        print(f'    EXCEPTION: {e}')
        return False


def try_extract_7z(iso_path: str, iso_file: str, dest: str) -> bool:
    """Try extracting a file with 7z."""
    dest_dir = str(Path(dest).parent)
    print(f'\n    7z e {iso_path} {iso_file} -o{dest_dir} -y')
    try:
        r = subprocess.run(
            ['7z', 'e', iso_path, iso_file, f'-o{dest_dir}', '-y'],
            capture_output=True, text=True, timeout=120)
        if r.stdout.strip():
            print(f'    stdout (last 200 chars): ...{r.stdout.strip()[-200:]}')
        if r.stderr.strip():
            print(f'    stderr: {r.stderr.strip()[:500]}')
        print(f'    return code: {r.returncode}')
        extracted = Path(dest_dir) / Path(iso_file).name
        if extracted.exists():
            size = extracted.stat().st_size
            if str(extracted) != dest:
                extracted.rename(dest)
            print(f'    SUCCESS: extracted {size:,} bytes')
            return True
        print(f'    FAILED: extracted file not found at {extracted}')
        return False
    except Exception as e:
        print(f'    EXCEPTION: {e}')
        return False


def try_extract_bsdtar(iso_path: str, iso_file: str, dest: str) -> bool:
    """Try extracting a file with bsdtar."""
    dest_dir = str(Path(dest).parent)
    print(f'\n    bsdtar -xf {iso_path} -C {dest_dir} {iso_file}')
    try:
        r = subprocess.run(
            ['bsdtar', '-xf', iso_path, '-C', dest_dir, iso_file],
            capture_output=True, text=True, timeout=120)
        if r.stdout.strip():
            print(f'    stdout: {r.stdout.strip()[:200]}')
        if r.stderr.strip():
            print(f'    stderr: {r.stderr.strip()[:500]}')
        print(f'    return code: {r.returncode}')
        extracted = Path(dest_dir) / iso_file
        if extracted.exists():
            size = extracted.stat().st_size
            shutil.move(str(extracted), dest)
            print(f'    SUCCESS: extracted {size:,} bytes')
            return True
        print(f'    FAILED: extracted file not found at {extracted}')
        return False
    except Exception as e:
        print(f'    EXCEPTION: {e}')
        return False


def try_extract(iso_path: str, iso_file: str, dest: str, tools: dict) -> bool:
    """Try all available tools to extract a file."""
    for tool_name, extract_fn in [
        ('xorriso', try_extract_xorriso),
        ('7z',      try_extract_7z),
        ('bsdtar',  try_extract_bsdtar),
    ]:
        if tools.get(tool_name):
            if extract_fn(iso_path, iso_file, dest):
                return True
    return False


def test_known_paths(iso_path: str, iso_type: str, tools: dict) -> tuple[str, str] | None:
    """Test all known kernel paths for this ISO type."""
    header(f'Testing known kernel paths (detected type: {iso_type})')

    candidates = KERNEL_PATHS.get(iso_type, []) + GENERIC_KERNEL_PATHS
    print(f'\n  Will test {len(candidates)} kernel/initrd path pairs:\n')
    for i, (k, ir) in enumerate(candidates):
        src = f'  [{KERNEL_PATHS.get(iso_type, []).__contains__((k, ir)) and "distro" or "generic"}]'
        print(f'    {i+1:2d}. kernel={k}  initrd={ir}  {src}')

    with tempfile.TemporaryDirectory(prefix='netventoy_debug_') as tmpdir:
        for i, (ksrc, isrc) in enumerate(candidates):
            print(f'\n  --- Attempt {i+1}/{len(candidates)}: {ksrc} ---')
            vmlinuz = os.path.join(tmpdir, 'vmlinuz')
            initrd = os.path.join(tmpdir, 'initrd')

            # Clean up from previous attempt
            for f in (vmlinuz, initrd):
                if os.path.exists(f):
                    os.unlink(f)

            print(f'  Trying kernel: {ksrc}')
            if try_extract(iso_path, ksrc, vmlinuz, tools):
                print(f'\n  Kernel FOUND! Trying paired initrd: {isrc}')
                if try_extract(iso_path, isrc, initrd, tools):
                    print(f'\n  SUCCESS: Found kernel+initrd pair!')
                    return (ksrc, isrc)

                # Try alternate initrds
                alternates = ['casper/initrd.lz', 'live/initrd1.img',
                              'isolinux/initrd', 'boot/initramfs.img',
                              'boot/initramfs', 'install.amd/initrd.gz',
                              'install.386/initrd.gz']
                for alt in alternates:
                    if alt == isrc:
                        continue
                    if os.path.exists(initrd):
                        os.unlink(initrd)
                    print(f'  Trying alternate initrd: {alt}')
                    if try_extract(iso_path, alt, initrd, tools):
                        print(f'\n  SUCCESS: Found kernel+initrd pair!')
                        return (ksrc, alt)
                print(f'  WARNING: Kernel found but no matching initrd!')
            else:
                print(f'  Kernel not found at {ksrc}')

    return None


def extract_to_dir(iso_path: str, kernel_path: str, initrd_path: str,
                   output_dir: str, tools: dict) -> bool:
    """Extract found kernel+initrd to the specified output directory."""
    header(f'Extracting to {output_dir}')
    os.makedirs(output_dir, exist_ok=True)

    vmlinuz = os.path.join(output_dir, 'vmlinuz')
    initrd = os.path.join(output_dir, 'initrd')

    print(f'  Extracting kernel: {kernel_path} -> {vmlinuz}')
    if not try_extract(iso_path, kernel_path, vmlinuz, tools):
        print('  FAILED to extract kernel!')
        return False

    print(f'\n  Extracting initrd: {initrd_path} -> {initrd}')
    if not try_extract(iso_path, initrd_path, initrd, tools):
        print('  FAILED to extract initrd!')
        return False

    print(f'\n  Done! Files extracted to {output_dir}/')
    print(f'    vmlinuz: {os.path.getsize(vmlinuz):,} bytes')
    print(f'    initrd:  {os.path.getsize(initrd):,} bytes')
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Debug ISO kernel extraction for netventoy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('iso', help='Path to ISO file')
    parser.add_argument('--extract', '-e', metavar='DIR',
                        help='Extract found kernel+initrd to this directory')
    parser.add_argument('--type', '-t',
                        help='Override auto-detected ISO type '
                             f'(choices: {", ".join(KERNEL_PATHS.keys())}, generic)')
    parser.add_argument('--list-only', '-l', action='store_true',
                        help='Only list ISO contents, do not attempt extraction')
    args = parser.parse_args()

    iso_path = os.path.abspath(args.iso)
    if not os.path.isfile(iso_path):
        print(f'ERROR: File not found: {iso_path}', file=sys.stderr)
        sys.exit(1)

    print(f'ISO: {iso_path}')
    print(f'Size: {os.path.getsize(iso_path):,} bytes')

    # Step 1: Check tools
    tools = check_tools()

    if not any(tools.get(t) for t in ('xorriso', '7z', 'bsdtar')):
        print('\nERROR: No extraction tools found! Install one of:')
        print('  apt install xorriso    # recommended')
        print('  apt install p7zip-full')
        print('  apt install libarchive-tools')
        sys.exit(1)

    # Step 2: List ISO contents
    files = list_iso_files(iso_path, tools)

    if files:
        # Show interesting files
        print('\n  Potentially interesting paths:')
        for f in sorted(files):
            basename = f.rstrip('/').rsplit('/', 1)[-1] if '/' in f else f
            if (KERNEL_PATTERNS.search(basename) or
                    INITRD_PATTERNS.search(basename) or
                    'boot' in f.lower() or 'install' in f.lower() or
                    'pxe' in f.lower()):
                print(f'    {f}')

    # Step 3: Find candidates from file listing
    if files:
        find_kernel_candidates(files)

    if args.list_only:
        if files:
            header('Complete file listing')
            for f in sorted(files):
                print(f'  {f}')
        return

    # Step 4: Detect type and test known paths
    iso_type = args.type or detect_iso_type(iso_path)
    result = test_known_paths(iso_path, iso_type, tools)

    if result:
        header('RESULT: Kernel extraction would SUCCEED')
        print(f'  Kernel path: {result[0]}')
        print(f'  Initrd path: {result[1]}')

        if args.extract:
            extract_to_dir(iso_path, result[0], result[1], args.extract, tools)
    else:
        header('RESULT: Kernel extraction FAILED')
        print('  None of the known kernel paths matched this ISO.')
        if files:
            print('\n  Suggestion: Review the file listing above and check if')
            print('  there are kernel/initrd files at unexpected paths.')
            print('  You may need to add new paths to _KERNEL_PATHS in app.py')
        sys.exit(1)


if __name__ == '__main__':
    main()
