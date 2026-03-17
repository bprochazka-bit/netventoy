# NetVentoy 🌐

> **Ventoy for the Network Age** — Self-hosted PXE/iPXE network boot server.
> Debian 13 (Trixie) native — zero pip dependencies.

---

## Dependencies — APT only

```
sudo apt install python3-flask python3-werkzeug python3-watchdog dnsmasq
```

That's it. No `pip`, no virtual environment, no external package index.

| APT package        | Purpose                              |
|--------------------|--------------------------------------|
| `python3-flask`    | Web UI & REST API                    |
| `python3-werkzeug` | WSGI utilities, secure file upload   |
| `python3-watchdog` | inotify-based filesystem watching    |
| `dnsmasq`          | Proxy DHCP + TFTP server             |

---

## Quick Start

```bash
# 1. Install
sudo apt install python3-flask python3-werkzeug python3-watchdog dnsmasq wget

# 2. Set up
sudo bash setup.sh

# 3. Run
sudo python3 app.py
```

Open **http://YOUR-IP:5000**

---

## How It Works

```
PXE client boots
  ↓  DHCP broadcast
Router → NetVentoy dnsmasq (proxy DHCP, port 67)
  ↓  hands out PXE info
Client downloads iPXE bootloader via TFTP (port 69)
  ↓
iPXE fetches  http://SERVER:5000/boot.ipxe
  ↓
Boot menu appears on screen
  ↓
User picks ISO → ISO streamed over HTTP → OS boots
```

---

## Features

| Feature | Detail |
|---|---|
| **Directory menus** | Sub-folders in `isos/` become submenus in the boot menu |
| **Pinned images** | Any ISO can be pinned to the top of the main menu |
| **inotify watching** | Drop `.iso` into `isos/` folder, menu updates in ~1s |
| **Web uploads** | Drag & drop with live progress bar, up to 50 GB |
| **Auto-detection** | Detects Ubuntu, Debian, Fedora, Arch, etc. and pre-fills kernel args |
| **Per-ISO metadata** | Custom name, icon (emoji), description, kernel args |
| **Enable/disable** | Remove ISOs from the menu without deleting the file |
| **BIOS + UEFI** | `undionly.kpxe` for BIOS, `ipxe.efi` for UEFI |
| **Proxy DHCP** | Works alongside your existing router/DHCP server |

---

## ISO Organisation

```
isos/
├── ubuntu-24.04-lts.iso          ← appears in main menu
├── debian-12.iso                 ← appears in main menu
├── linux/
│   ├── arch-2024.11.01.iso       ← "linux" submenu
│   └── fedora-40.iso             ← "linux" submenu
├── tools/
│   ├── memtest86-7.0.iso         ← "tools" submenu
│   └── gparted-1.6.0.iso         ← "tools" submenu
└── windows/
    └── win11.iso                 ← "windows" submenu (needs wimboot)
```

---

## Router / DHCP Configuration

You need to tell your DHCP server where the PXE server is.

### Any DHCP server
| Setting | Value |
|---|---|
| Next Server (`siaddr`) | `YOUR-SERVER-IP` |
| Boot filename (BIOS) | `undionly.kpxe` |
| Boot filename (UEFI) | `ipxe.efi` |

### pfSense / OPNsense
*Services → DHCP Server → Network Booting*
- Enable: ✓
- Next Server: `YOUR-SERVER-IP`
- Default BIOS file: `undionly.kpxe`

### OpenWrt / DD-WRT (dnsmasq)
Add to `/etc/dnsmasq.conf`:
```
dhcp-boot=undionly.kpxe,netventoy,192.168.1.X
```

---

## Linux ISO Boot Notes

For most Linux live ISOs, NetVentoy uses **memdisk** as a fallback (loads the
entire ISO into RAM). For large ISOs (> 2 GB) this may fail depending on available
RAM. The preferred approach for those is to extract the kernel and initrd from the
ISO and serve them directly.

The web UI lets you set custom kernel arguments per ISO. The auto-detected defaults
work for most common distros.

### Extracting kernel/initrd (optional, for large ISOs)

```bash
# Mount the ISO
sudo mount -o loop,ro /opt/netventoy/isos/ubuntu-24.04.iso /mnt

# Copy boot files
sudo mkdir -p /opt/netventoy/kernels/ubuntu
sudo cp /mnt/casper/vmlinuz  /opt/netventoy/kernels/ubuntu/
sudo cp /mnt/casper/initrd   /opt/netventoy/kernels/ubuntu/
sudo umount /mnt
```

Then edit the ISO in the UI and set the kernel args to:
```
boot=casper url=http://YOUR-IP:5000/isos/ubuntu-24.04.iso quiet splash ---
```

---

## Windows (advanced)

Windows ISOs require [wimboot](https://ipxe.org/wimboot). This is not automated.
The UI will display a placeholder entry. See the iPXE wimboot documentation for
the full procedure.

---

## Running as a Service

```bash
# Install service (setup.sh does this automatically if run as root)
sudo cp netventoy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netventoy

# Check status
sudo systemctl status netventoy
sudo journalctl -u netventoy -f
```

---

## Ports

| Port | Proto | Purpose |
|------|-------|---------|
| 5000 | TCP   | Web UI + HTTP ISO serving |
| 67   | UDP   | DHCP proxy (dnsmasq) — **root required** |
| 69   | UDP   | TFTP bootloader delivery (dnsmasq) |

---

## Troubleshooting

**Client doesn't get PXE boot option**
- Check UDP 67 isn't blocked: `sudo ss -ulnp | grep :67`
- Verify dnsmasq is running: check the status dot in the UI header
- Make sure your router is sending the `next-server` option

**Menu appears but ISO won't boot**
- Open the ISO in the UI → check kernel args match the distro
- View the "Boot Menu" panel to see the generated iPXE script
- For large ISOs: RAM must exceed ISO size when using memdisk fallback

**dnsmasq won't start**
- Must run as root: `sudo python3 app.py`
- Kill any existing dnsmasq: `sudo systemctl stop dnsmasq`
- Check port conflicts: `sudo ss -ulnp | grep :67`
