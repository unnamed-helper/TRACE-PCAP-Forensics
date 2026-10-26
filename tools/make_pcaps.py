#!/usr/bin/env python3
"""Generate SYNTHETIC test captures (pcap + pcapng) for verifying TRACE.
These are test fixtures only - they are not shipped as sample detections.
Requires scapy (test-time only; TRACE itself has no Python dependencies)."""
import base64, random, struct, sys, os
from scapy.all import (Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, wrpcap, PcapNgWriter, PcapWriter)

random.seed(7)
out = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(out, exist_ok=True)
T0 = 1760400000.0
pk = []
clock = [T0]

def add(p, dt=0.01):
    clock[0] += dt
    p.time = clock[0]
    pk.append(p)

M = {"c": "aa:bb:cc:00:00:20", "s": "aa:bb:cc:00:00:05", "gw": "aa:bb:cc:00:00:01", "atk": "aa:bb:cc:00:00:66"}

def tcp_session(src, dst, sport, dport, c_payload=None, s_payload=None, smac=M["c"], dmac=M["s"], close=True, dt=0.02):
    isn_c, isn_s = random.randint(1000, 2**31), random.randint(1000, 2**31)
    E = lambda a, b: Ether(src=a, dst=b)
    add(E(smac, dmac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=isn_c), dt)
    add(E(dmac, smac) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=isn_s, ack=isn_c + 1), dt)
    add(E(smac, dmac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=isn_c + 1, ack=isn_s + 1), dt)
    cs, ss = isn_c + 1, isn_s + 1
    if c_payload:
        add(E(smac, dmac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=cs, ack=ss) / Raw(c_payload), dt)
        cs += len(c_payload)
        add(E(dmac, smac) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=ss, ack=cs), dt)
    if s_payload:
        add(E(dmac, smac) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=ss, ack=cs) / Raw(s_payload), dt)
        ss += len(s_payload)
        add(E(smac, dmac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=cs, ack=ss), dt)
    if close:
        add(E(smac, dmac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=cs, ack=ss), dt)
        add(E(dmac, smac) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA", seq=ss, ack=cs + 1), dt)
        add(E(smac, dmac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=cs + 1, ack=ss + 1), dt)

def client_hello(sni):
    name = sni.encode()
    sn = b"\x00" + struct.pack(">H", len(name)) + name
    ext_sni = struct.pack(">HH", 0, len(sn) + 2) + struct.pack(">H", len(sn)) + sn
    ext_ver = struct.pack(">HH", 43, 3) + b"\x02\x03\x04"
    alpn = b"\x00\x0c\x02h2\x08http/1.1"
    ext_alpn = struct.pack(">HH", 16, len(alpn)) + alpn
    exts = ext_sni + ext_ver + ext_alpn
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack(">H", 4) + b"\x13\x01\x13\x02" + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs

# --- ARP
add(Ether(src=M["c"], dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=M["c"], psrc="10.0.0.20", pdst="10.0.0.1"))
add(Ether(src=M["gw"], dst=M["c"]) / ARP(op=2, hwsrc=M["gw"], psrc="10.0.0.1", hwdst=M["c"], pdst="10.0.0.20"))
# ARP spoof: second MAC claims 10.0.0.1
add(Ether(src=M["atk"], dst=M["c"]) / ARP(op=2, hwsrc=M["atk"], psrc="10.0.0.1", hwdst=M["c"], pdst="10.0.0.20"))

# --- DNS
def dns_pair(client, name, ans_ip, sport=None, rcode=0):
    sport = sport or random.randint(20000, 60000)
    q = Ether(src=M["c"], dst=M["gw"]) / IP(src=client, dst="10.0.0.2") / UDP(sport=sport, dport=53) / DNS(id=random.randint(1, 65000), rd=1, qd=DNSQR(qname=name))
    add(q, 0.02)
    r = Ether(src=M["gw"], dst=M["c"]) / IP(src="10.0.0.2", dst=client) / UDP(sport=53, dport=sport) / DNS(id=q[DNS].id, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=60, rdata=ans_ip) if rcode == 0 else None)
    add(r, 0.02)

dns_pair("10.0.0.20", "intranet.corp.example", "10.0.0.5")
dns_pair("10.0.0.20", "update.badc2.example", "203.0.113.9")
dns_pair("10.0.0.20", "www.example.org", "93.184.216.34")
# DNS tunnelling style: many long high-entropy labels under one parent
for i in range(30):
    lab = base64.b32encode(os.urandom(18)).decode().lower().strip("=")
    dns_pair("10.0.0.30", f"{lab}.t.evil-tunnel.example", "198.51.100.7", rcode=0 if i % 3 else 3)

# --- HTTP (with a Basic auth request and an admin URI + sqlmap UA)
req = b"GET /index.html HTTP/1.1\r\nHost: intranet.corp.example\r\nUser-Agent: Mozilla/5.0 (X11; Linux)\r\nAccept: */*\r\n\r\n"
res = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: 38\r\n\r\n<html><body>Hello from intranet</body></html>"
tcp_session("10.0.0.20", "10.0.0.5", 51001, 80, req, res)
req2 = b"GET /admin/login.php?id=1%27%20OR%201=1-- HTTP/1.1\r\nHost: intranet.corp.example\r\nUser-Agent: sqlmap/1.7\r\nAuthorization: Basic YWRtaW46c2VjcmV0\r\n\r\n"
res2 = b"HTTP/1.1 403 Forbidden\r\nServer: nginx\r\nContent-Type: text/plain\r\n\r\nno"
tcp_session("10.0.0.20", "10.0.0.5", 51002, 80, req2, res2)
# multi-segment stream to test follow-stream
big = b"POST /upload HTTP/1.1\r\nHost: files.corp.example\r\nContent-Length: 3000\r\n\r\n" + b"A" * 1000
tcp_session("10.0.0.20", "10.0.0.5", 51003, 8080, big, b"HTTP/1.1 201 Created\r\n\r\n")

# --- TLS
tcp_session("10.0.0.20", "93.184.216.34", 51010, 443, client_hello("www.example.org"), b"\x16\x03\x03\x00\x04\x02\x00\x00\x00")
tcp_session("10.0.0.21", "203.0.113.50", 51011, 443, client_hello("cdn.update-check.example"), None, close=False)

# --- ICMP and NTP
for i in range(3):
    add(Ether(src=M["c"], dst=M["gw"]) / IP(src="10.0.0.20", dst="10.0.0.1") / ICMP(id=1, seq=i) / Raw(b"abcdefgh" * 4), 0.05)
    add(Ether(src=M["gw"], dst=M["c"]) / IP(src="10.0.0.1", dst="10.0.0.20") / ICMP(type=0, id=1, seq=i) / Raw(b"abcdefgh" * 4), 0.01)
add(Ether(src=M["c"], dst=M["gw"]) / IP(src="10.0.0.20", dst="10.0.0.1") / UDP(sport=123, dport=123) / Raw(b"\x1b" + b"\x00" * 47))

# --- IPv6
add(Ether(src=M["c"], dst=M["gw"]) / IPv6(src="2001:db8::20", dst="2001:db8::1") / TCP(sport=40000, dport=22, flags="S", seq=1))
add(Ether(src=M["gw"], dst=M["c"]) / IPv6(src="2001:db8::1", dst="2001:db8::20") / TCP(sport=22, dport=40000, flags="SA", seq=9, ack=2))
add(Ether(src=M["c"], dst=M["gw"]) / IPv6(src="2001:db8::20", dst="2001:db8::1") / TCP(sport=40000, dport=22, flags="PA", seq=2, ack=10) / Raw(b"SSH-2.0-OpenSSH_9.6\r\n"))

# --- FTP cleartext creds
tcp_session("10.0.0.21", "10.0.0.5", 51020, 21, b"USER alice\r\nPASS hunter2\r\n", b"230 Login successful\r\n")

# --- port scan: 10.0.0.66 -> 10.0.0.5, ports 1..60, only 22/80 answer
for port in range(1, 61):
    sp = 40000 + port
    add(Ether(src=M["atk"], dst=M["s"]) / IP(src="10.0.0.66", dst="10.0.0.5") / TCP(sport=sp, dport=port, flags="S", seq=100), 0.003)
    if port in (22, 80):
        add(Ether(src=M["s"], dst=M["atk"]) / IP(src="10.0.0.5", dst="10.0.0.66") / TCP(sport=port, dport=sp, flags="SA", seq=500, ack=101), 0.002)
        add(Ether(src=M["atk"], dst=M["s"]) / IP(src="10.0.0.66", dst="10.0.0.5") / TCP(sport=sp, dport=port, flags="R", seq=101), 0.002)
    else:
        add(Ether(src=M["s"], dst=M["atk"]) / IP(src="10.0.0.5", dst="10.0.0.66") / TCP(sport=port, dport=sp, flags="RA", seq=0, ack=101), 0.002)

# --- beaconing: 12 check-ins every 30 s to 203.0.113.9:8443 (with small jitter)
for i in range(12):
    clock[0] += 30 + random.uniform(-0.8, 0.8)
    tcp_session("10.0.0.20", "203.0.113.9", 52000 + i, 8443, b"ping %d" % i, b"pong")

# --- vlan tagged frame
from scapy.all import Dot1Q
add(Ether(src=M["c"], dst=M["gw"]) / Dot1Q(vlan=42) / IP(src="10.0.0.20", dst="10.0.0.1") / UDP(sport=5555, dport=5556) / Raw(b"vlan"))

pk.sort(key=lambda p: p.time)
print("packets:", len(pk))
wrpcap(os.path.join(out, "test.pcap"), pk)
w = PcapNgWriter(os.path.join(out, "test.pcapng"))
for p in pk:
    w.write(p)
w.close()
# nanosecond pcap via PcapWriter nano=True
w = PcapWriter(os.path.join(out, "test-nano.pcap"), nano=True)
for p in pk:
    w.write(p)
w.close()
print("wrote", os.listdir(out))
