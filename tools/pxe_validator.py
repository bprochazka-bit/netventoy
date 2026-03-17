#!/usr/bin/env python3
"""
PXE/DHCP Validation Tool
========================
Performs a full DHCP handshake and validates PXE-specific options,
then optionally tests TFTP connectivity to the next-server.

Uses AF_PACKET raw sockets (Layer 2) so it works even when
NetworkManager is active and holding port 68.

Requires root/sudo.
Usage:
    sudo python3 pxe_validator.py --interface eth0
    sudo python3 pxe_validator.py --interface eth0 --test-tftp
    sudo python3 pxe_validator.py --interface eth0 --test-tftp --tftp-server 192.168.1.50
    sudo python3 pxe_validator.py --interface eth0 --debug
"""

import argparse
import socket
import struct
import random
import time
import sys
import os
import select
from datetime import datetime

# ──────────────────────────────────────────────
# ANSI Colors
# ──────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GREY   = "\033[90m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════╗
║          PXE / DHCP Validation Tool v1.1             ║
║     Full handshake + TFTP connectivity tester        ║
║     AF_PACKET mode — works alongside NetworkManager  ║
╚══════════════════════════════════════════════════════╝{C.RESET}
""")

def log(level, msg):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    icons = {
        "INFO": f"{C.BLUE}[*]{C.RESET}",
        "OK":   f"{C.GREEN}[✓]{C.RESET}",
        "WARN": f"{C.YELLOW}[!]{C.RESET}",
        "ERR":  f"{C.RED}[✗]{C.RESET}",
        "SEND": f"{C.CYAN}[→]{C.RESET}",
        "RECV": f"{C.GREEN}[←]{C.RESET}",
        "DBG":  f"{C.GREY}[d]{C.RESET}",
    }
    icon = icons.get(level, "[?]")
    print(f"{C.GREY}{ts}{C.RESET} {icon} {msg}")

def section(title):
    print(f"\n{C.BOLD}{C.WHITE}{'─'*54}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{'─'*54}{C.RESET}")

# ──────────────────────────────────────────────
# DHCP Option Constants
# ──────────────────────────────────────────────
DHCP_DISCOVER   = 1
DHCP_OFFER      = 2
DHCP_REQUEST    = 3
DHCP_ACK        = 5
DHCP_NAK        = 6

OPT_SUBNET_MASK = 1
OPT_ROUTER      = 3
OPT_DNS         = 6
OPT_DOMAIN      = 15
OPT_BROADCAST   = 28
OPT_REQUESTED_IP= 50
OPT_LEASE_TIME  = 51
OPT_MSG_TYPE    = 53
OPT_SERVER_ID   = 54
OPT_PARAM_REQ   = 55
OPT_VENDOR_CLASS= 60
OPT_CLIENT_ID   = 61
OPT_TFTP_SERVER = 66
OPT_BOOTFILE    = 67
OPT_END         = 255

DHCP_MAGIC      = b'\x63\x82\x53\x63'

MSG_NAMES = {1:'DISCOVER',2:'OFFER',3:'REQUEST',4:'DECLINE',
             5:'ACK',6:'NAK',7:'RELEASE',8:'INFORM'}

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
def random_mac():
    return bytes([0x02] + [random.randint(0, 0xff) for _ in range(5)])

def mac_to_str(b):
    return ':'.join(f'{x:02x}' for x in b)

def ip_to_str(b):
    return '.'.join(str(x) for x in b)

def str_to_ip(s):
    return bytes(int(x) for x in s.split('.'))

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

# ──────────────────────────────────────────────
# Frame Building (AF_PACKET / Layer 2)
# ──────────────────────────────────────────────
def build_eth_udp_frame(src_mac, dhcp_payload, src_port=68, dst_port=67):
    """Build full Ethernet+IP+UDP frame around a DHCP payload."""
    # UDP
    udp_len    = 8 + len(dhcp_payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)

    # IP
    ip_tot_len = 20 + udp_len
    ip_id      = random.randint(0, 0xFFFF)
    ip_hdr_raw = struct.pack('!BBHHHBBH4s4s',
        0x45, 0x00, ip_tot_len, ip_id, 0x4000,
        64, 17, 0,
        b'\x00\x00\x00\x00',
        b'\xff\xff\xff\xff')
    ip_csum    = checksum(ip_hdr_raw)
    ip_header  = struct.pack('!BBHHHBBH4s4s',
        0x45, 0x00, ip_tot_len, ip_id, 0x4000,
        64, 17, ip_csum,
        b'\x00\x00\x00\x00',
        b'\xff\xff\xff\xff')

    # Ethernet
    eth = b'\xff\xff\xff\xff\xff\xff' + src_mac + b'\x08\x00'

    return eth + ip_header + udp_header + dhcp_payload

def extract_dhcp_from_frame(frame):
    """
    Pull DHCP payload out of a raw Ethernet frame.
    Returns (dhcp_bytes, src_ip_str) or (None, None).
    """
    try:
        if len(frame) < 42:
            return None, None

        eth_type = struct.unpack('!H', frame[12:14])[0]
        if eth_type != 0x0800:
            return None, None

        ip_ihl   = (frame[14] & 0x0F) * 4
        ip_proto = frame[23]
        if ip_proto != 17:
            return None, None

        src_ip   = ip_to_str(frame[26:30])
        udp_off  = 14 + ip_ihl
        src_port = struct.unpack('!H', frame[udp_off:udp_off+2])[0]
        dst_port = struct.unpack('!H', frame[udp_off+2:udp_off+4])[0]

        if src_port != 67 or dst_port != 68:
            return None, None

        return frame[udp_off+8:], src_ip
    except Exception:
        return None, None

# ──────────────────────────────────────────────
# DHCP Packet Building
# ──────────────────────────────────────────────
def build_discover(xid, mac, vendor_class):
    pkt = struct.pack('!BBBBIHH4s4s4s4s16s64s128sI',
        1, 1, 6, 0, xid, 0, 0x8000,
        b'\x00'*4, b'\x00'*4, b'\x00'*4, b'\x00'*4,
        mac + b'\x00'*10,
        b'\x00'*64, b'\x00'*128,
        0x63825363)
    opts  = bytes([OPT_MSG_TYPE, 1, DHCP_DISCOVER])
    opts += bytes([OPT_PARAM_REQ, 8,
                   OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_DOMAIN,
                   OPT_BROADCAST, OPT_TFTP_SERVER, OPT_BOOTFILE, 43])
    vc    = vendor_class.encode()
    opts += bytes([OPT_VENDOR_CLASS, len(vc)]) + vc
    cid   = bytes([0x01]) + mac
    opts += bytes([OPT_CLIENT_ID, len(cid)]) + cid
    opts += bytes([OPT_END])
    return pkt + opts

def build_request(xid, mac, offered_ip, server_ip):
    pkt = struct.pack('!BBBBIHH4s4s4s4s16s64s128sI',
        1, 1, 6, 0, xid, 0, 0x8000,
        b'\x00'*4, b'\x00'*4, b'\x00'*4, b'\x00'*4,
        mac + b'\x00'*10,
        b'\x00'*64, b'\x00'*128,
        0x63825363)
    opts  = bytes([OPT_MSG_TYPE, 1, DHCP_REQUEST])
    opts += bytes([OPT_REQUESTED_IP, 4]) + str_to_ip(offered_ip)
    opts += bytes([OPT_SERVER_ID,    4]) + str_to_ip(server_ip)
    opts += bytes([OPT_END])
    return pkt + opts

def build_proxy_request(xid, mac, proxy_ip, vendor_class="PXEClient:Arch:00000:UNDI:002001"):
    """DHCPREQUEST sent unicast to proxy DHCP server on port 4011."""
    pkt = struct.pack('!BBBBIHH4s4s4s4s16s64s128sI',
        1,1,6,0,xid,0,0,  # flags=0 unicast
        b'\x00'*4, b'\x00'*4,
        bytes(int(x) for x in proxy_ip.split('.')),
        b'\x00'*4,
        mac+b'\x00'*10,
        b'\x00'*64, b'\x00'*128, 0x63825363)
    opts  = bytes([OPT_MSG_TYPE,1,DHCP_REQUEST])
    vc    = vendor_class.encode()
    opts += bytes([OPT_VENDOR_CLASS,len(vc)])+vc
    opts += bytes([OPT_END])
    return pkt+opts

def is_proxy_offer(p):
    """Proxy DHCP offer: yiaddr is 0.0.0.0 but has PXE options."""
    return (p['yiaddr'] == '0.0.0.0' and (
        p['siaddr'] not in ('0.0.0.0', '', None) or
        OPT_TFTP_SERVER in p['options'] or
        OPT_BOOTFILE    in p['options']))

def merge_pxe_info(regular, proxy=None):
    """Extract PXE fields, preferring proxy offer when present."""
    src = proxy if proxy else regular
    return {
        'offered_ip':  regular['yiaddr'],
        'server_ip':   opt_ip(regular, OPT_SERVER_ID) or regular['siaddr'],
        'next_server': (src['siaddr'] if src['siaddr'] not in ('0.0.0.0','') else None)
                       or opt_str(src, OPT_TFTP_SERVER),
        'tftp_server': opt_str(src, OPT_TFTP_SERVER) or
                       (src['siaddr'] if src['siaddr'] not in ('0.0.0.0','') else None),
        'boot_file':   src['file'] or opt_str(src, OPT_BOOTFILE) or '',
        'from_proxy':  proxy is not None,
        'pxe_ok':      False,  # set after validation
    }

# ──────────────────────────────────────────────
# DHCP Packet Parsing
# ──────────────────────────────────────────────
def parse_dhcp(data):
    if len(data) < 240:
        return None
    f = struct.unpack('!BBBBIHH4s4s4s4s16s64s128sI', data[:240])
    r = {
        'op':     f[0], 'xid':    f[4],
        'ciaddr': ip_to_str(f[7]),  'yiaddr': ip_to_str(f[8]),
        'siaddr': ip_to_str(f[9]),  'giaddr': ip_to_str(f[10]),
        'chaddr': mac_to_str(f[11][:6]),
        'sname':  f[12].rstrip(b'\x00').decode(errors='replace'),
        'file':   f[13].rstrip(b'\x00').decode(errors='replace'),
        'options': {}
    }
    pos = 240  # always start after the 240-byte fixed header (magic cookie included)
    while pos < len(data):
        opt = data[pos]
        if opt == 0:   pos += 1; continue
        if opt == 255: break
        if pos+1 >= len(data): break
        l = data[pos+1]
        r['options'][opt] = data[pos+2:pos+2+l]
        pos += 2 + l
    return r

def msg_type(p):
    t = p['options'].get(OPT_MSG_TYPE, b'\x00')
    return t[0] if t else 0

def opt_ip(p, o):
    v = p['options'].get(o)
    return ip_to_str(v[:4]) if v and len(v) >= 4 else None

def opt_str(p, o):
    v = p['options'].get(o)
    return v.rstrip(b'\x00').decode(errors='replace') if v else None

def opt_int(p, o):
    v = p['options'].get(o)
    return int.from_bytes(v, 'big') if v else None

# ──────────────────────────────────────────────
# DHCP Handshake
# ──────────────────────────────────────────────
def do_dhcp_handshake(interface, timeout, vendor_class, debug, relax_xid=False):
    section("PHASE 1 — DHCP DISCOVER")

    mac = random_mac()
    xid = random.randint(1, 0xFFFFFFFF)

    log("INFO", f"Interface      : {C.BOLD}{interface}{C.RESET}")
    log("INFO", f"Spoofed MAC    : {C.BOLD}{mac_to_str(mac)}{C.RESET}")
    log("INFO", f"Transaction ID : {C.BOLD}0x{xid:08x}{C.RESET}")
    log("INFO", f"Vendor Class   : {C.BOLD}{vendor_class}{C.RESET}")
    log("INFO", f"Socket mode    : {C.BOLD}AF_PACKET raw L2{C.RESET}")

    # RX socket must be open BEFORE we transmit to avoid race condition
    # where the OFFER arrives before we start listening
    try:
        rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        rx.bind((interface, 0))
        rx.setblocking(False)
    except PermissionError:
        log("ERR", "Permission denied — run with sudo"); sys.exit(1)
    except OSError as e:
        log("ERR", f"RX socket error: {e}"); sys.exit(1)

    try:
        tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        tx.bind((interface, 0))
    except OSError as e:
        log("ERR", f"TX socket error: {e}"); sys.exit(1)

    disc  = build_discover(xid, mac, vendor_class)
    frame = build_eth_udp_frame(mac, disc)
    log("SEND", f"DHCPDISCOVER → 255.255.255.255:67  ({len(disc)} bytes DHCP / {len(frame)} on wire)")
    tx.send(frame)

    # ── Wait for OFFER(s) — collect both regular and proxy ──
    section("PHASE 2 — DHCP OFFER")
    log("INFO", f"Waiting up to {timeout}s for DHCPOFFER (regular + proxy)...")

    regular_offer = None
    proxy_offer   = None
    deadline      = time.time() + timeout
    frame_count   = 0
    dhcp_count    = 0

    while time.time() < deadline:
        # Once we have a regular offer, give proxy 0.5s to also arrive
        if regular_offer and not proxy_offer:
            remaining = min(0.5, deadline - time.time())
            if remaining <= 0:
                break
            ready = select.select([rx], [], [], remaining)
        else:
            ready = select.select([rx], [], [], deadline - time.time())
        if not ready[0]:
            break
        try:
            raw, _ = rx.recvfrom(65535)
            frame_count += 1
            if debug:
                eth_type = struct.unpack('!H', raw[12:14])[0] if len(raw) >= 14 else 0
                smac     = mac_to_str(raw[6:12]) if len(raw) >= 12 else '??'
                log("DBG", f"frame #{frame_count:04d}  etype=0x{eth_type:04x}  src={smac}  len={len(raw)}")

            dhcp_data, src_ip = extract_dhcp_from_frame(raw)
            if dhcp_data is None:
                continue

            dhcp_count += 1
            parsed = parse_dhcp(dhcp_data)
            if not parsed:
                continue

            mt = msg_type(parsed)
            if debug:
                log("DBG", f"  DHCP {MSG_NAMES.get(mt,str(mt))}  xid=0x{parsed['xid']:08x}  "
                            f"yiaddr={parsed['yiaddr']}  siaddr={parsed['siaddr']}  from={src_ip}")

            if parsed['xid'] != xid:
                continue
            if mt != DHCP_OFFER:
                continue

            if is_proxy_offer(parsed):
                proxy_offer = parsed
                log("RECV", f"{C.CYAN}Proxy DHCP OFFER received from {src_ip} "
                            f"(siaddr={parsed['siaddr']}){C.RESET}")
            else:
                regular_offer = parsed
                log("RECV", f"{C.GREEN}Regular DHCP OFFER received from {src_ip} "
                            f"(yiaddr={parsed['yiaddr']}){C.RESET}")

            # Done if we have both, or if we already had regular and proxy window expired
            if regular_offer and proxy_offer:
                break

        except Exception as e:
            log("WARN", f"  exception in receive loop: {e}")
            import traceback; traceback.print_exc()
            continue

    if debug:
        log("DBG", f"Loop done: {frame_count} total frames, {dhcp_count} DHCP frames")

    if not regular_offer:
        log("ERR", f"{C.RED}No regular DHCPOFFER received within {timeout}s{C.RESET}")
        if frame_count == 0:
            log("WARN", "Zero frames received — is the interface up and linked?")
        elif dhcp_count == 0:
            log("WARN", f"{frame_count} frames seen but none were DHCP — check USG DHCP scope")
        else:
            log("WARN", f"{dhcp_count} DHCP frames seen but none matched XID 0x{xid:08x}")
        tx.close(); rx.close()
        return None

    if proxy_offer:
        log("OK", f"{C.GREEN}Both regular + proxy DHCP offers received{C.RESET}")
    else:
        log("INFO", "No proxy DHCP offer received — using regular offer for PXE info")

    offer = regular_offer

    # ── Print offer details ──
    pxe_info    = merge_pxe_info(regular_offer, proxy_offer)
    offered_ip  = pxe_info['offered_ip']
    server_ip   = pxe_info['server_ip']
    next_server = pxe_info['next_server'] or '0.0.0.0'
    boot_file   = pxe_info['boot_file']
    tftp_server = pxe_info['tftp_server'] or next_server
    subnet_mask = opt_ip(offer, OPT_SUBNET_MASK)
    router      = opt_ip(offer, OPT_ROUTER)
    dns_raw     = offer['options'].get(OPT_DNS, b'')
    dns_list    = [ip_to_str(dns_raw[i:i+4]) for i in range(0, len(dns_raw), 4)]
    lease_time  = opt_int(offer, OPT_LEASE_TIME)
    domain      = opt_str(offer, OPT_DOMAIN)

    if pxe_info['from_proxy']:
        log("INFO", f"PXE info sourced from {C.CYAN}proxy DHCP offer{C.RESET}")
    else:
        log("INFO", f"PXE info sourced from regular DHCP offer")
    print()
    print(f"  {'Offered IP':<24} {C.BOLD}{C.GREEN}{offered_ip}{C.RESET}")
    print(f"  {'DHCP Server':<24} {C.BOLD}{server_ip}{C.RESET}")
    print(f"  {'Subnet Mask':<24} {subnet_mask or C.GREY+'(not provided)'+C.RESET}")
    print(f"  {'Router/Gateway':<24} {router or C.GREY+'(not provided)'+C.RESET}")
    print(f"  {'DNS Servers':<24} {', '.join(dns_list) if dns_list else C.GREY+'(not provided)'+C.RESET}")
    print(f"  {'Domain':<24} {domain or C.GREY+'(not provided)'+C.RESET}")
    print(f"  {'Lease Time':<24} {str(lease_time)+'s' if lease_time else C.GREY+'(not provided)'+C.RESET}")
    print()
    print(f"  {C.BOLD}── PXE Fields ──{C.RESET}")

    pxe_ok = True

    if next_server and next_server != '0.0.0.0':
        print(f"  {'next-server (siaddr)':<24} {C.GREEN}{C.BOLD}{next_server}{C.RESET}")
    else:
        print(f"  {'next-server (siaddr)':<24} {C.RED}NOT SET (0.0.0.0){C.RESET}")
        log("WARN", "siaddr is 0.0.0.0 — client won't know where to fetch boot file!")
        pxe_ok = False

    if boot_file:
        print(f"  {'Boot File':<24} {C.GREEN}{C.BOLD}{boot_file}{C.RESET}")
    else:
        print(f"  {'Boot File':<24} {C.RED}NOT SET{C.RESET}")
        log("WARN", "No boot filename — PXE client won't know what to load!")
        pxe_ok = False

    tftp_opt = opt_str(offer, OPT_TFTP_SERVER)
    print(f"  {'TFTP Server (opt 66)':<24} "
          f"{C.GREEN+tftp_opt+C.RESET if tftp_opt else C.GREY+'(not set — using siaddr)'+C.RESET}")

    boot_opt = opt_str(offer, OPT_BOOTFILE)
    print(f"  {'Boot File (opt 67)':<24} "
          f"{C.GREEN+boot_opt+C.RESET if boot_opt else C.GREY+'(not set — using file field)'+C.RESET}")

    vendor_r = offer['options'].get(OPT_VENDOR_CLASS)
    print(f"  {'Vendor Class (opt 60)':<24} "
          f"{C.GREEN+vendor_r.decode(errors='replace')+C.RESET if vendor_r else C.GREY+'(not returned)'+C.RESET}")

    print()
    if pxe_ok:
        log("OK", f"{C.GREEN}DHCP offer contains required PXE fields ✓{C.RESET}")
    else:
        log("WARN", f"{C.YELLOW}DHCP offer MISSING required PXE fields — PXE boot will fail{C.RESET}")

    # ── DHCP REQUEST ──
    section("PHASE 3 — DHCP REQUEST")
    req   = build_request(xid, mac, offered_ip, server_ip)
    frame = build_eth_udp_frame(mac, req)
    log("SEND", f"DHCPREQUEST for {offered_ip} → 255.255.255.255:67")
    tx.send(frame)

    # ── Wait for ACK ──
    section("PHASE 4 — DHCP ACK")
    log("INFO", f"Waiting up to {timeout}s for DHCPACK...")

    ack      = None
    deadline = time.time() + timeout

    while time.time() < deadline:
        ready = select.select([rx], [], [], deadline - time.time())
        if not ready[0]:
            break
        try:
            raw, _ = rx.recvfrom(65535)
            dhcp_data, src_ip = extract_dhcp_from_frame(raw)
            if dhcp_data is None: continue
            parsed = parse_dhcp(dhcp_data)
            if not parsed: continue
            if parsed['xid'] != xid: continue
            mt = msg_type(parsed)
            if debug:
                log("DBG", f"DHCP {MSG_NAMES.get(mt,str(mt))} xid=0x{parsed['xid']:08x} from {src_ip}")
            if mt == DHCP_ACK:
                ack = parsed; break
            elif mt == DHCP_NAK:
                log("ERR", f"{C.RED}DHCPNAK — server rejected request{C.RESET}")
                tx.close(); rx.close(); return None
        except Exception as e:
            if debug: log("DBG", f"exception: {e}")
            continue

    tx.close(); rx.close()

    if not ack:
        log("ERR", f"{C.RED}No DHCPACK received within {timeout}s{C.RESET}")
        return None

    log("OK", f"{C.GREEN}DHCPACK received — full handshake complete!{C.RESET}")
    print(f"\n  {'Confirmed IP':<24} {C.GREEN}{C.BOLD}{ack['yiaddr']}{C.RESET}")

    # ── Proxy DHCP request/ack (port 4011) ──
    proxy_ack = None
    if proxy_offer:
        proxy_ip = proxy_offer['siaddr'] if proxy_offer['siaddr'] not in ('0.0.0.0','') \
                   else opt_str(proxy_offer, OPT_TFTP_SERVER)
        if proxy_ip:
            section("PHASE 4b — PROXY DHCP HANDSHAKE (port 4011)")
            log("INFO", f"Sending proxy DHCP REQUEST to {proxy_ip}:4011")
            try:
                proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                proxy_sock.settimeout(timeout)
                proxy_sock.bind(('', 68))
                proxy_req = build_proxy_request(xid, mac, proxy_ip, vendor_class)
                proxy_sock.sendto(proxy_req, (proxy_ip, PROXY_DHCP_PORT))
                log("SEND", f"Proxy DHCPREQUEST sent ({len(proxy_req)} bytes)")

                try:
                    data, addr = proxy_sock.recvfrom(4096)
                    p = parse_dhcp(data)
                    if p and p['xid'] == xid and msg_type(p) == DHCP_ACK:
                        proxy_ack = p
                        log("OK", f"{C.GREEN}Proxy DHCP ACK received from {addr[0]}:{addr[1]}{C.RESET}")
                        pxe_boot  = p['file'] or opt_str(p, OPT_BOOTFILE) or boot_file
                        pxe_tftp  = opt_str(p, OPT_TFTP_SERVER) or \
                                    (p['siaddr'] if p['siaddr'] != '0.0.0.0' else None) or tftp_server
                        log("INFO", f"  Proxy boot file   : {C.BOLD}{pxe_boot}{C.RESET}")
                        log("INFO", f"  Proxy TFTP server : {C.BOLD}{pxe_tftp}{C.RESET}")
                        boot_file   = pxe_boot
                        tftp_server = pxe_tftp
                    else:
                        log("WARN", "Proxy DHCP response was not an ACK or XID mismatch")
                except socket.timeout:
                    log("WARN", f"Proxy DHCP timeout — no response from {proxy_ip}:4011")
                    log("WARN", "Check: dnsmasq proxy mode configured? (dhcp-range=x.x.x.x,proxy)")
                proxy_sock.close()
            except OSError as e:
                log("WARN", f"Proxy DHCP socket error: {e}")

    eff_tftp = tftp_server if tftp_server and tftp_server != '0.0.0.0' else next_server
    return {
        'offered_ip':   offered_ip,
        'server_ip':    server_ip,
        'next_server':  next_server,
        'tftp_server':  eff_tftp,
        'boot_file':    boot_file,
        'pxe_ok':       pxe_ok,
        'proxy_used':   proxy_offer is not None,
        'proxy_acked':  proxy_ack is not None,
    }

# ──────────────────────────────────────────────
# TFTP Test
# ──────────────────────────────────────────────
def test_tftp(tftp_server, boot_file, timeout):
    section("PHASE 5 — TFTP CONNECTIVITY TEST")

    if not tftp_server or tftp_server == '0.0.0.0':
        log("ERR", "No TFTP server IP — skipping TFTP test"); return False

    file_to_get = boot_file if boot_file else "pxelinux.0"
    log("INFO", f"TFTP Server : {C.BOLD}{tftp_server}{C.RESET}")
    log("INFO", f"File        : {C.BOLD}{file_to_get}{C.RESET}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        rrq = b'\x00\x01' + file_to_get.encode() + b'\x00octet\x00'
        log("SEND", f"TFTP RRQ → {tftp_server}:69")
        sock.sendto(rrq, (tftp_server, 69))

        try:
            data, addr = sock.recvfrom(516)
            opcode = struct.unpack('!H', data[:2])[0]

            if opcode == 3:  # DATA
                block = struct.unpack('!H', data[2:4])[0]
                size  = len(data) - 4
                log("RECV", f"{C.GREEN}TFTP DATA block {block} ({size} bytes){C.RESET}")
                log("OK",   f"{C.GREEN}TFTP server reachable and serving files!{C.RESET}")
                sock.sendto(struct.pack('!HH', 4, block), addr)
                sock.close(); return True

            elif opcode == 5:  # ERROR
                ecode = struct.unpack('!H', data[2:4])[0]
                emsg  = data[4:].rstrip(b'\x00').decode(errors='replace')
                emeanings = {1:"File not found", 2:"Access violation",
                             3:"Disk full", 4:"Illegal operation"}
                log("WARN", f"TFTP ERROR {ecode} ({emeanings.get(ecode,'unknown')}): {emsg}")
                if ecode == 1:
                    log("INFO", f"TFTP IS reachable but '{file_to_get}' not found on server")
                    log("INFO", "Check tftp-root path in dnsmasq.conf and that the file exists")
                sock.close(); return False

            else:
                log("WARN", f"Unexpected TFTP opcode: {opcode}")
                sock.close(); return False

        except socket.timeout:
            log("ERR",  f"{C.RED}TFTP timeout — no response from {tftp_server}:69{C.RESET}")
            log("WARN", "Possible causes:")
            log("WARN", "  • dnsmasq enable-tftp not set in dnsmasq.conf")
            log("WARN", "  • dnsmasq not running  →  systemctl status dnsmasq")
            log("WARN", "  • Proxmox VM firewall blocking UDP 69")
            log("WARN", "  • dnsmasq not bound to correct interface")
            log("WARN", f"  • Run on the dnsmasq box: ss -ulnp | grep 69")
            sock.close(); return False

    except Exception as e:
        log("ERR", f"TFTP error: {e}"); return False

# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────
def print_summary(dhcp_result, tftp_result):
    section("SUMMARY")
    checks = [
        ("DHCP Handshake (DISCOVER→OFFER→REQUEST→ACK)", dhcp_result is not None),
        ("next-server (siaddr) present in offer",
            dhcp_result and dhcp_result['next_server'] not in ('0.0.0.0','',None)),
        ("Boot filename present in offer",
            dhcp_result and bool(dhcp_result.get('boot_file'))),
    ]
    if tftp_result is not None:
        checks.append(("TFTP server reachable and responding", tftp_result))

    all_pass = True
    for label, passed in checks:
        icon = f"{C.GREEN}✓{C.RESET}" if passed else f"{C.RED}✗{C.RESET}"
        print(f"  {icon}  {label}")
        if not passed: all_pass = False

    print()
    if all_pass:
        log("OK",   f"{C.GREEN}{C.BOLD}All checks passed — PXE environment looks healthy!{C.RESET}")
    else:
        log("WARN", f"{C.YELLOW}{C.BOLD}Some checks failed — see details above{C.RESET}")

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="PXE/DHCP Validation Tool — AF_PACKET raw socket edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 pxe_validator.py --interface enp86s0
  sudo python3 pxe_validator.py --interface enp86s0 --test-tftp
  sudo python3 pxe_validator.py --interface enp86s0 --test-tftp --tftp-server 10.50.50.16
  sudo python3 pxe_validator.py --interface enp86s0 --debug
  sudo python3 pxe_validator.py --interface enp86s0 --vendor-class "PXEClient:Arch:00007:UNDI:003016"
        """)
    parser.add_argument('--interface',    required=True)
    parser.add_argument('--timeout',      type=int, default=5)
    parser.add_argument('--test-tftp',    action='store_true')
    parser.add_argument('--tftp-server',  default=None)
    parser.add_argument('--tftp-file',    default=None)
    parser.add_argument('--vendor-class', default="PXEClient:Arch:00000:UNDI:002001")
    parser.add_argument('--relax-xid',    action='store_true',
                        help='Accept OFFER even if XID does not match (for debugging)')
    parser.add_argument('--debug',        action='store_true',
                        help='Print every received frame during DHCP listen')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(f"{C.RED}Error: requires root. Run with sudo.{C.RESET}")
        sys.exit(1)

    banner()
    log("INFO", f"Interface: {C.BOLD}{args.interface}{C.RESET}")

    dhcp_result = do_dhcp_handshake(
        args.interface, args.timeout, args.vendor_class, args.debug, args.relax_xid)

    tftp_result = None
    if args.test_tftp:
        tftp_server = args.tftp_server or (dhcp_result['tftp_server'] if dhcp_result else None)
        boot_file   = args.tftp_file   or (dhcp_result['boot_file']   if dhcp_result else None)
        tftp_result = test_tftp(tftp_server, boot_file, args.timeout)
    elif dhcp_result and dhcp_result.get('pxe_ok'):
        log("INFO", "PXE fields present — auto-running TFTP test...")
        tftp_result = test_tftp(dhcp_result['tftp_server'], dhcp_result['boot_file'], args.timeout)
    else:
        section("PHASE 5 — TFTP CONNECTIVITY TEST")
        log("INFO", "Skipping TFTP test (use --test-tftp to enable)")

    print_summary(dhcp_result, tftp_result)
    print()

if __name__ == '__main__':
    main()
