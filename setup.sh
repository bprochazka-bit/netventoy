#!/bin/bash
# NetVentoy setup — Debian 13 (Trixie)
# Installs all required APT packages and stages the boot chain:
#   EFI (Secure Boot): shimx64.efi → grubnetx64.efi → grub.cfg
#   EFI (HTTP Boot):   same binaries served over HTTP
#   BIOS:              grub i386-pc core.0 → grub.cfg
#
# APT only. No pip. No external downloads except iPXE BIOS fallback.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TFTP_DIR="$SCRIPT_DIR/tftp"
GRUB_DIR="$TFTP_DIR/grub"

B='\033[0;34m'; G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'
info(){ echo -e "${B}[info]${N}  $*"; }
ok()  { echo -e "${G}[ok]${N}    $*"; }
warn(){ echo -e "${Y}[warn]${N}  $*"; }
err() { echo -e "${R}[error]${N} $*"; exit 1; }

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   NetVentoy — Debian 13 Setup                ║"
echo "║   shim + grub boot chain (Secure Boot ready) ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Root check ────────────────────────────────────────────────────────────────
[ "$EUID" -ne 0 ] && err "Must run as root: sudo bash setup.sh"

# ── OS check ──────────────────────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    info "OS: $PRETTY_NAME"
    [[ "$ID" != "debian" ]] && warn "Targeting Debian 13; other distros may need path adjustments"
fi

# ── APT packages ──────────────────────────────────────────────────────────────
info "Installing APT packages..."

PACKAGES=(
    # Python web stack
    python3-flask
    python3-werkzeug
    python3-watchdog
    # PXE/TFTP
    dnsmasq
    # ISO extraction
    xorriso
    # EFI boot chain — signed binaries from Debian
    shim-signed           # provides shimx64.efi (Microsoft-trusted)
    grub-efi-amd64-signed # provides grubnetx64.efi.signed (distro-signed netboot grub)
    grub-efi-amd64-bin    # provides unsigned grub EFI modules
    # BIOS boot chain
    grub-pc-bin           # provides grub-mknetdir for BIOS PXE core image
    # Utilities
    wget
)

apt-get update -qq
apt-get install -y "${PACKAGES[@]}" 2>&1 | grep -E '(Unpacking|Setting up|already installed)' || true
ok "APT packages installed"

# ── Disable system dnsmasq service ────────────────────────────────────────────
# NetVentoy spawns its own dnsmasq instance with a custom config.
# The system service would conflict on port 67/69.
if systemctl is-active --quiet dnsmasq 2>/dev/null; then
    warn "Stopping system dnsmasq (NetVentoy manages its own instance)"
    systemctl stop dnsmasq
    systemctl disable dnsmasq
fi

# ── Create directory structure ────────────────────────────────────────────────
info "Creating directory structure..."
mkdir -p \
    "$TFTP_DIR" \
    "$GRUB_DIR" \
    "$SCRIPT_DIR/isos" \
    "$SCRIPT_DIR/kernels" \
    "$SCRIPT_DIR/wimboot" \
    "$SCRIPT_DIR/config" \
    "$SCRIPT_DIR/static"
ok "Directories ready"

# ── Stage EFI boot chain ──────────────────────────────────────────────────────
info "Staging EFI boot chain (shim → grub)..."

# shimx64.efi — the Microsoft-trusted shim from Debian's shim-signed package.
# Debian 13 installs the signed shim to /usr/lib/shim/
SHIM_PATHS=(
    "/usr/lib/shim/shimx64.efi.signed.latest"
    "/usr/lib/shim/shimx64.efi.signed"
    "/usr/lib/shim/shimx64.efi"
    "/boot/efi/EFI/debian/shimx64.efi"
)
SHIM_SRC=""
for p in "${SHIM_PATHS[@]}"; do
    if [ -f "$p" ]; then SHIM_SRC="$p"; break; fi
done

if [ -n "$SHIM_SRC" ]; then
    cp -f "$SHIM_SRC" "$TFTP_DIR/shimx64.efi"
    ok "shimx64.efi  ← $SHIM_SRC"
else
    warn "shimx64.efi not found in expected paths — Secure Boot EFI boot will not work"
    warn "Try: dpkg -L shim-signed | grep efi"
fi

# shimia32.efi — 32-bit EFI shim (rare but worth including)
SHIM32_PATHS=(
    "/usr/lib/shim/shimia32.efi.signed"
    "/usr/lib/shim/shimia32.efi"
)
for p in "${SHIM32_PATHS[@]}"; do
    if [ -f "$p" ]; then
        cp -f "$p" "$TFTP_DIR/shimia32.efi"
        ok "shimia32.efi ← $p"
        break
    fi
done

# grubnetx64.efi.signed — the distro-signed netboot grub EFI binary.
# shim validates this against the distro's embedded certificate.
# grub-efi-amd64-signed installs to /usr/lib/grub/x86_64-efi-signed/
GRUB_EFI_PATHS=(
    "/usr/lib/grub/x86_64-efi-signed/grubnetx64.efi.signed"
    "/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed"
)
GRUB_EFI_SRC=""
for p in "${GRUB_EFI_PATHS[@]}"; do
    if [ -f "$p" ]; then GRUB_EFI_SRC="$p"; break; fi
done

if [ -n "$GRUB_EFI_SRC" ]; then
    # shim looks for grubx64.efi in the same directory it was loaded from
    cp -f "$GRUB_EFI_SRC" "$TFTP_DIR/grubx64.efi"
    ok "grubx64.efi  ← $GRUB_EFI_SRC"
else
    warn "grubnetx64.efi.signed not found — EFI grub stage will not work"
    warn "Try: dpkg -L grub-efi-amd64-signed | grep efi"
fi

# grub.cfg must be found by grub at (tftp)/grub/grub.cfg
# We write a minimal stub here; the app regenerates the real one at startup.
if [ ! -f "$GRUB_DIR/grub.cfg" ]; then
    cat > "$GRUB_DIR/grub.cfg" << 'GRUBCFG'
# NetVentoy grub.cfg stub — will be replaced at startup
set timeout=10
menuentry "NetVentoy loading..." {
    echo "Please wait — NetVentoy is generating the boot menu."
    sleep 3
}
GRUBCFG
    ok "grub.cfg stub written"
fi

# ── Stage BIOS boot chain ─────────────────────────────────────────────────────
info "Generating BIOS PXE boot image (grub-mknetdir)..."

# grub-mknetdir generates a self-contained BIOS PXE directory under
# $GRUB_DIR/i386-pc/  containing core.0 (the chainloaded PXE image)
# and all required grub modules.
# core.0 is the file dnsmasq hands to BIOS PXE clients via DHCP option.
grub-mknetdir \
    --net-directory="$GRUB_DIR" \
    --subdir="i386-pc" \
    2>&1 | tail -5

if [ -f "$GRUB_DIR/i386-pc/core.0" ]; then
    ok "BIOS grub core.0 generated at grub/i386-pc/core.0"
else
    warn "grub-mknetdir may have failed — check output above"
fi

# grub-mknetdir also generates an EFI image but we prefer the signed one.
# Remove the unsigned EFI output to avoid confusion.
rm -f "$GRUB_DIR/x86_64-efi/core.efi" 2>/dev/null || true

# grub needs its module files at (pxe)/grub/x86_64-efi/ for EFI grub.
# grubnetx64.efi.signed has most modules built-in for netboot but
# copy them anyway so grub can load optional modules (font, etc).
GRUB_EFI_MODS="/usr/lib/grub/x86_64-efi"
if [ -d "$GRUB_EFI_MODS" ]; then
    mkdir -p "$GRUB_DIR/x86_64-efi"
    cp -r "$GRUB_EFI_MODS/"*.mod "$GRUB_DIR/x86_64-efi/" 2>/dev/null || true
    ok "grub EFI modules staged"
fi

# ── Proxmox / bridge netfilter check ─────────────────────────────────────────
# When running inside a Proxmox VM (or any host with br_netfilter loaded),
# bridged DHCP broadcasts are routed through iptables and often silently
# dropped before reaching the VM.  This makes ProxyDHCP completely invisible
# to PXE clients.  The fix is to disable bridge-nf-call-iptables on the
# HYPERVISOR HOST (not inside the VM).
BRNF="/proc/sys/net/bridge/bridge-nf-call-iptables"
if [ -f "$BRNF" ] && [ "$(cat "$BRNF")" = "1" ]; then
    warn "br_netfilter is active — DHCP broadcasts through bridges will be filtered"
    warn "If running inside a VM, run this on the Proxmox/hypervisor HOST:"
    echo ""
    echo "    # Immediate fix:"
    echo "    echo 0 > /proc/sys/net/bridge/bridge-nf-call-iptables"
    echo "    echo 0 > /proc/sys/net/bridge/bridge-nf-call-ip6tables"
    echo ""
    echo "    # Persistent across reboots (on the Proxmox host):"
    echo "    cat > /etc/sysctl.d/99-netventoy-bridge.conf << 'SYSCTL'"
    echo "    net.bridge.bridge-nf-call-iptables = 0"
    echo "    net.bridge.bridge-nf-call-ip6tables = 0"
    echo "    SYSCTL"
    echo "    sysctl --system"
    echo ""
fi

# ── Systemd service ───────────────────────────────────────────────────────────
if [ -f "$SCRIPT_DIR/netventoy.service" ]; then
    sed "s|/opt/netventoy|$SCRIPT_DIR|g" \
        "$SCRIPT_DIR/netventoy.service" \
        > /etc/systemd/system/netventoy.service
    systemctl daemon-reload
    ok "Systemd service installed (not yet enabled)"
fi

# ── Print binary inventory ────────────────────────────────────────────────────
echo ""
info "TFTP directory inventory:"
find "$TFTP_DIR" -type f | sort | while read f; do
    size=$(du -sh "$f" 2>/dev/null | cut -f1)
    echo "    $size  ${f#$TFTP_DIR/}"
done

# ── Summary ───────────────────────────────────────────────────────────────────
IP=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('8.8.8.8', 80))
print(s.getsockname()[0])
s.close()
" 2>/dev/null || echo "YOUR-IP")

echo ""
echo "═══════════════════════════════════════════════════"
ok "Setup complete!"
echo ""
echo "  Start:"
echo "    sudo python3 $SCRIPT_DIR/app.py"
echo ""
echo "  Web UI:"
echo "    http://${IP}:5000"
echo ""
echo "  USG / Router:"
echo "    Remove all PXE / next-server options."
echo "    dnsmasq ProxyDHCP handles PXE for all clients."
echo ""
echo "  Boot chain:"
echo "    EFI (Secure Boot) → shimx64.efi → grubx64.efi → grub.cfg"
echo "    EFI (HTTP Boot)   → http://${IP}:5000/tftp/shimx64.efi"
echo "    BIOS              → grub/i386-pc/core.0 → grub.cfg"
echo "═══════════════════════════════════════════════════"
