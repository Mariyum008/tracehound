"""Turn a packet capture into tidy event tables (packets, DNS, HTTP, TLS, cleartext auth)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # hide 'packet truncated' noise on live files

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")
# Form fields / headers that carry secrets in cleartext
CRED_PATTERNS = [
    (re.compile(rb"(?:^|[&?\s])(pass|passwd|password|pwd|pin|secret)=", re.I), "password field in request"),
    (re.compile(rb"authorization:\s*basic\s", re.I), "HTTP Basic auth header"),
]
MAIL_FTP_PORTS = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 25: "SMTP", 587: "SMTP"}
RCODE_NAMES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


@dataclass
class ParsedCapture:
    path: str
    packets: list = field(default_factory=list)
    dns: list = field(default_factory=list)
    http: list = field(default_factory=list)
    tls: list = field(default_factory=list)
    auth: list = field(default_factory=list)
    kind: str = "pcap"                              # "pcap" or "zeek"
    refs: dict = field(default_factory=dict)        # zeek only: record id -> "conn.log uid=..."


def _tls_sni(payload: bytes) -> str | None:
    # Minimal TLS ClientHello parser that extracts the server_name extension
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        i = 5 + 4 + 2 + 32  # record hdr, handshake hdr, version, random
        i += 1 + payload[i]  # session id
        i += 2 + int.from_bytes(payload[i:i + 2], "big")  # cipher suites
        i += 1 + payload[i]  # compression methods
        end = i + 2 + int.from_bytes(payload[i:i + 2], "big")
        i += 2
        while i + 4 <= min(end, len(payload)):
            ext_type = int.from_bytes(payload[i:i + 2], "big")
            ext_len = int.from_bytes(payload[i + 2:i + 4], "big")
            if ext_type == 0:  # server_name
                name_len = int.from_bytes(payload[i + 7:i + 9], "big")
                return payload[i + 9:i + 9 + name_len].decode(errors="ignore") or None
            i += 4 + ext_len
    except (IndexError, ValueError):
        return None
    return None


def _parse_http(payload: bytes):
    # Returns (method, uri, host, user_agent) for an HTTP request, else None
    if not payload.startswith(HTTP_METHODS):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode(errors="ignore")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return parts[0], parts[1], headers.get("host", ""), headers.get("user-agent", "")


def _dns_answers(dns) -> list[str]:
    # Collect A/AAAA answer IPs from a DNS response
    ips = []
    try:
        answers = dns.an if isinstance(dns.an, list) else [dns.an[i] for i in range(dns.ancount)]
        for rr in answers:
            if getattr(rr, "type", None) in (1, 28):
                ips.append(str(rr.rdata))
    except Exception:
        pass
    return ips


def _safe_packets(reader):
    # Yield packets until the file ends or the last packet is cut off (a capture still being written)
    it = iter(reader)
    while True:
        try:
            yield next(it)
        except StopIteration:
            return
        except Exception:
            return


def _process(cap: ParsedCapture, frame: int, pkt) -> None:
    """Extract one packet into the tables."""
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return
    ts = float(pkt.time)
    sport = dport = None
    flags, proto, payload = "", "OTHER", b""
    if TCP in pkt:
        proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
        flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
    if Raw in pkt:
        payload = bytes(pkt[Raw].load)
    cap.packets.append((frame, ts, src, dst, proto, sport, dport, flags, len(pkt), len(payload)))

    # DNS queries and responses
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        d = pkt[DNS]
        qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".").lower()
        is_resp = int(d.qr) == 1
        rcode = RCODE_NAMES.get(int(d.rcode), str(d.rcode)) if is_resp else None
        answers = ",".join(_dns_answers(d)) if is_resp else ""
        cap.dns.append((frame, ts, src, dst, qname, is_resp, rcode, answers))
        return

    if proto != "TCP" or not payload:
        return

    # HTTP requests and cleartext credentials in them
    http = _parse_http(payload)
    if http:
        method, uri, host, ua = http
        cap.http.append((frame, ts, src, dst, dport, method, uri, host, ua))
        for pattern, label in CRED_PATTERNS:
            if pattern.search(payload):
                cap.auth.append((frame, ts, src, dst, dport, "HTTP", label))
                break
        return

    # TLS ClientHello server names
    sni = _tls_sni(payload)
    if sni:
        cap.tls.append((frame, ts, src, dst, dport, sni.lower()))
        return

    # Legacy cleartext logins (FTP, POP3, IMAP, SMTP, Telnet)
    service = MAIL_FTP_PORTS.get(dport)
    if service and re.match(rb"(PASS |AUTH (PLAIN|LOGIN)|\S+ LOGIN )", payload, re.I):
        cap.auth.append((frame, ts, src, dst, dport, service, f"{service} login command"))


def parse_pcap(path: str, max_packets: int | None = None) -> ParsedCapture:
    """Stream the capture once and extract every table we need."""
    cap = ParsedCapture(path=path)
    try:
        reader = PcapReader(path)
    except Exception:  # empty or header-only file, e.g. a live capture that just started
        return cap
    with reader:
        for frame, pkt in enumerate(_safe_packets(reader), start=1):
            if max_packets and frame > max_packets:
                break
            try:
                _process(cap, frame, pkt)
            except Exception:  # one malformed packet should never stop the analysis
                continue
    return cap
