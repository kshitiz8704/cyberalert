"""Module C - Network IDS using Scapy (needs admin/root + Npcap on Windows)."""
import time
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
from common import CFG, entropy, send_alert

C = CFG["nids"]
W = C["window"]
scan = defaultdict(deque)      # src -> (time, dst_port)
syn = defaultdict(deque)       # (src,dst,port) -> time
icmp = defaultdict(deque)      # src -> time
dns_q = defaultdict(deque)     # src -> time


def prune(dq, now, key=lambda x: x):
    while dq and now - key(dq[0]) > W:
        dq.popleft()


def handle(pkt):
    if IP not in pkt:
        return
    now, src, dst = time.time(), pkt[IP].src, pkt[IP].dst

    # TCP SYN (no ACK) = start of a connection attempt
    if TCP in pkt and (int(pkt[TCP].flags) & 0x12) == 0x02:
        port = pkt[TCP].dport
        scan[src].append((now, port))
        prune(scan[src], now, lambda x: x[0])
        ports = {p for _, p in scan[src]}
        if len(ports) >= C["port_scan_ports"]:
            send_alert("Network", "Port Scan", "High", src, f"{len(ports)} distinct ports probed in {W}s")
        k = (src, dst, port)
        syn[k].append(now)
        prune(syn[k], now)
        if len(syn[k]) >= C["syn_repeat"]:
            send_alert("Network", "Repeated Connections", "Medium", src, f"{len(syn[k])} SYN packets to {dst}:{port} in {W}s")

    # ICMP echo request (ping)
    elif ICMP in pkt and pkt[ICMP].type == 8:
        icmp[src].append(now)
        prune(icmp[src], now)
        if len(icmp[src]) >= C["icmp_flood"]:
            send_alert("Network", "ICMP Flood", "Medium", src, f"{len(icmp[src])} ping requests in {W}s")

    # DNS query
    if UDP in pkt and pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
        name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".").lower()
        dns_q[src].append(now)
        prune(dns_q[src], now)
        if any(name == d or name.endswith("." + d) for d in C["bad_domains"]):
            send_alert("Network", "Blacklisted Domain", "High", src, f"DNS query for {name}")
        label = name.split(".")[0]
        if len(name) > 50 or (len(label) > 25 and entropy(label.encode()) > 3.5):
            send_alert("Network", "Suspicious DNS Query", "Medium", src, f"Long/random domain (possible tunneling/DGA): {name[:60]}")
        if len(dns_q[src]) >= C["dns_per_window"]:
            send_alert("Network", "DNS Flood", "Low", src, f"{len(dns_q[src])} DNS queries in {W}s")


def run():
    print("[nids] sniffing on", C["interface"] or "default interface")
    try:
        sniff(iface=C["interface"], prn=handle, store=False, filter="ip")
    except Exception as e:
        print("[nids] ERROR (run as Administrator/root and install Npcap on Windows):", e)
