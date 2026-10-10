"""Synthetic captures for demos and tests: a full breach scenario and a clean baseline."""
from __future__ import annotations

import random
import struct

from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

T0 = 1_760_000_000.0
VICTIM, CLEAN_HOST, DNS_SERVER, INTRANET = "192.168.1.20", "192.168.1.15", "192.168.1.1", "192.168.1.10"
DROPPER_IP, C2_IP, C2_DOMAIN = "198.51.100.7", "203.0.113.50", "q7x9k2m4vb8z.top"


def client_hello(sni: str) -> bytes:
    # Minimal but valid TLS 1.2 ClientHello carrying an SNI extension
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(sni_ext)) + sni_ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


class Builder:
    """Collects packets with explicit timestamps."""

    def __init__(self, seed: int = 7):
        self.pkts, self.rng, self.port = [], random.Random(seed), 49152

    def add(self, t: float, pkt):
        pkt.time = T0 + t
        self.pkts.append(pkt)

    def next_port(self) -> int:
        self.port += 1
        return self.port

    def dns(self, t, client, qname, answer=None, nx=False):
        qid = self.rng.randint(1, 65535)
        self.add(t, IP(src=client, dst=DNS_SERVER) / UDP(sport=self.next_port(), dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=qname)))
        resp = DNS(id=qid, qr=1, rd=1, ra=1, rcode=3 if nx else 0, qd=DNSQR(qname=qname),
                   an=DNSRR(rrname=qname, type="A", ttl=300, rdata=answer) if answer else [])
        self.add(t + 0.02, IP(src=DNS_SERVER, dst=client) / UDP(sport=53, dport=self.port) / resp)

    def handshake(self, t, src, dst, dport):
        sp = self.next_port()
        self.add(t, IP(src=src, dst=dst) / TCP(sport=sp, dport=dport, flags="S"))
        self.add(t + 0.03, IP(src=dst, dst=src) / TCP(sport=dport, dport=sp, flags="SA"))
        self.add(t + 0.04, IP(src=src, dst=dst) / TCP(sport=sp, dport=dport, flags="A"))
        return sp

    def https_visit(self, t, src, dst, sni, kb_down=20):
        sp = self.handshake(t, src, dst, 443)
        self.add(t + 0.05, IP(src=src, dst=dst) / TCP(sport=sp, dport=443, flags="PA") / Raw(client_hello(sni)))
        for i in range(max(1, kb_down // 1)):
            self.add(t + 0.1 + i * 0.001, IP(src=dst, dst=src) / TCP(sport=443, dport=sp, flags="PA") / Raw(bytes(1000)))

    def write(self, path: str) -> str:
        self.pkts.sort(key=lambda p: p.time)
        wrpcap(path, self.pkts)
        return path


def _normal_browsing(b: Builder, start: float, host: str):
    # Ordinary traffic so the detections must find the needle in the haystack
    sites = [("www.wikipedia.org", "208.80.154.224"), ("www.google.com", "142.250.72.4"),
             ("github.com", "140.82.112.3"), ("news.ycombinator.com", "209.216.230.207")]
    for i, (name, ip) in enumerate(sites):
        t = start + i * 37 + b.rng.random() * 5
        b.dns(t, host, name, ip)
        b.https_visit(t + 0.1, host, ip, name, kb_down=b.rng.randint(10, 40))


def write_breach_scenario(path: str) -> str:
    """Victim downloads a dropper, leaks a password, finds its C2 via DGA, beacons, scans the LAN and exfiltrates."""
    b = Builder()
    _normal_browsing(b, 0, CLEAN_HOST)
    _normal_browsing(b, 2, VICTIM)

    # 1. Dropper downloaded from a raw IP by a scripted client
    sp = b.handshake(200, VICTIM, DROPPER_IP, 80)
    req = (f"GET /docs/invoice_8841.exe HTTP/1.1\r\nHost: {DROPPER_IP}\r\nUser-Agent: Microsoft BITS/7.8\r\n\r\n").encode()
    b.add(200.05, IP(src=VICTIM, dst=DROPPER_IP) / TCP(sport=sp, dport=80, flags="PA") / Raw(req))
    for i in range(150):
        b.add(200.1 + i * 0.002, IP(src=DROPPER_IP, dst=VICTIM) / TCP(sport=80, dport=sp, flags="PA") / Raw(bytes(1400)))

    # 2. Password sent in cleartext to an intranet login page
    sp = b.handshake(260, VICTIM, INTRANET, 80)
    body = b"username=jsmith&password=Summer2026!"
    req = (f"POST /login HTTP/1.1\r\nHost: intranet.corp.local\r\nUser-Agent: Mozilla/5.0\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
    b.add(260.05, IP(src=VICTIM, dst=INTRANET) / TCP(sport=sp, dport=80, flags="PA") / Raw(req))

    # 3. DGA: the malware tries generated domains until one resolves
    for i in range(12):
        fake = "".join(b.rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(14)) + ".top"
        b.dns(300 + i * 0.5, VICTIM, fake, nx=True)
    b.dns(307, VICTIM, C2_DOMAIN, C2_IP)

    # 4. Beaconing to the C2 roughly every 60 seconds
    for i in range(10):
        b.https_visit(320 + i * 60 + b.rng.uniform(-1.5, 1.5), VICTIM, C2_IP, C2_DOMAIN, kb_down=1)

    # 5. Lateral movement: SMB sweep across the subnet
    for i, last in enumerate(range(30, 50)):
        target = f"192.168.1.{last}"
        p = b.next_port()
        b.add(950 + i * 0.1, IP(src=VICTIM, dst=target) / TCP(sport=p, dport=445, flags="S"))
        if last in (31, 42):
            b.add(950 + i * 0.1 + 0.01, IP(src=target, dst=VICTIM) / TCP(sport=445, dport=p, flags="SA"))

    # 6. Exfiltration: ~6.3 MB uploaded to the C2 server
    sp = b.handshake(1000, VICTIM, C2_IP, 443)
    for i in range(4500):
        b.add(1000.1 + i * 0.004, IP(src=VICTIM, dst=C2_IP) / TCP(sport=sp, dport=443, flags="PA") / Raw(bytes(1400)))
        if i % 50 == 0:
            b.add(1000.1 + i * 0.004 + 0.001, IP(src=C2_IP, dst=VICTIM) / TCP(sport=443, dport=sp, flags="A"))
    return b.write(path)


def write_clean_scenario(path: str) -> str:
    """Only normal browsing; a good tool should report nothing here."""
    b = Builder(seed=11)
    for k in range(3):
        _normal_browsing(b, k * 200, CLEAN_HOST)
        _normal_browsing(b, k * 200 + 3, VICTIM)
    return b.write(path)


# ---- Zeek-format version of the breach scenario ------------------------------------------

ZEEK_FIELDS = {
    "conn": ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
             "orig_bytes", "resp_bytes", "conn_state", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"],
    "dns": ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "query", "qtype_name",
            "rcode_name", "answers"],
    "http": ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "method", "host", "uri",
             "user_agent", "status_code", "username", "password"],
    "ssl": ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "version", "server_name", "established"],
}


def write_zeek_breach(folder: str, fmt: str = "tsv") -> str:
    """Write conn/dns/http/ssl logs (Zeek TSV or JSON) describing the same breach as write_breach_scenario."""
    import json as _json
    from pathlib import Path

    rng, logs, n = random.Random(7), {k: [] for k in ZEEK_FIELDS}, [0]

    def uid():
        n[0] += 1
        return f"C{n[0]:017d}"

    def conn(t, src, dst, dport, ob, rb, state="SF", history="ShADadFf", proto="tcp", service="-", dur=1.0):
        u, sport = uid(), 49152 + n[0]
        logs["conn"].append([T0 + t, u, src, sport, dst, dport, proto, service, dur, ob, rb, state, history,
                             max(1, ob // 1400), ob + 40, max(1 if rb else 0, rb // 1400), rb + (40 if rb else 0)])
        return u, sport

    def dns(t, client, q, answer=None, nx=False):
        logs["dns"].append([T0 + t, uid(), client, 50000 + n[0], DNS_SERVER, 53, "udp", q, "A",
                            "NXDOMAIN" if nx else "NOERROR", [answer] if answer else []])

    def https(t, src, dst, sni, kb=20):
        u, sp = conn(t, src, dst, 443, 600, kb * 1000, service="ssl")
        logs["ssl"].append([T0 + t + 0.05, u, src, sp, dst, 443, "TLSv13", sni, "T"])

    for host, start in ((CLEAN_HOST, 0), (VICTIM, 2)):  # normal browsing
        for i, (name, ip) in enumerate([("www.wikipedia.org", "208.80.154.224"), ("www.google.com", "142.250.72.4"),
                                        ("github.com", "140.82.112.3"), ("news.ycombinator.com", "209.216.230.207")]):
            t = start + i * 37 + rng.random() * 5
            dns(t, host, name, ip)
            https(t + 0.1, host, ip, name, rng.randint(10, 40))

    u, sp = conn(200, VICTIM, DROPPER_IP, 80, 120, 210_000, service="http")  # 1. dropper download
    logs["http"].append([T0 + 200.05, u, VICTIM, sp, DROPPER_IP, 80, "GET", DROPPER_IP, "/docs/invoice_8841.exe",
                         "Microsoft BITS/7.8", 200, None, None])
    u, sp = conn(260, VICTIM, INTRANET, 80, 300, 1200, service="http")  # 2. Basic-auth login in cleartext
    logs["http"].append([T0 + 260.05, u, VICTIM, sp, INTRANET, 80, "GET", "intranet.corp.local", "/login",
                         "Mozilla/5.0", 200, "jsmith", "<hidden>"])
    for i in range(12):  # 3. DGA lookups, then the C2 domain resolves
        fake = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(14)) + ".top"
        dns(300 + i * 0.5, VICTIM, fake, nx=True)
    dns(307, VICTIM, C2_DOMAIN, C2_IP)
    for i in range(10):  # 4. beaconing every ~60s
        https(320 + i * 60 + rng.uniform(-1.5, 1.5), VICTIM, C2_IP, C2_DOMAIN, kb=1)
    for i, last in enumerate(range(30, 50)):  # 5. SMB sweep: mostly unanswered SYNs
        conn(950 + i * 0.1, VICTIM, f"192.168.1.{last}", 445, 0, 0, state="S0", history="S", dur=0)
    conn(1000, VICTIM, C2_IP, 443, 6_300_000, 9_000, service="ssl", dur=18)  # 6. exfiltration

    out = Path(folder)
    out.mkdir(parents=True, exist_ok=True)
    for name, rows in logs.items():
        rows.sort(key=lambda r: r[0])
        fields = ZEEK_FIELDS[name]
        if fmt == "json":
            with open(out / f"{name}.log", "w") as fh:
                for r in rows:
                    fh.write(_json.dumps({k: v for k, v in zip(fields, r) if v is not None}) + "\n")
            continue
        def cell(v):
            return "-" if v is None else ("(empty)" if v == [] else ",".join(v) if isinstance(v, list)
                                          else f"{v:.6f}" if isinstance(v, float) else str(v))
        with open(out / f"{name}.log", "w") as fh:
            fh.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
                     f"#path\t{name}\n#fields\t" + "\t".join(fields) + "\n")
            for r in rows:
                fh.write("\t".join(cell(v) for v in r) + "\n")
            fh.write("#close\t2026-01-01-00-00-00\n")
    return str(out)
