"""Detection rules. Each rule returns Findings that point at the exact frames that prove them."""
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict

from .store import CaptureStore, is_internal

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
RISKY_EXTENSIONS = (".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".hta", ".vbs", ".js", ".jar", ".msi", ".iso", ".lnk")
RISKY_AGENTS = ("powershell", "curl/", "wget/", "certutil", "winhttp", "bitsadmin", "python-requests", "microsoft bits")
# Big CDNs/clouds generate random-looking names; skip them to avoid false DGA alerts
BENIGN_SUFFIXES = ("amazonaws.com", "cloudfront.net", "akamaiedge.net", "akamai.net", "googleapis.com",
                   "gvt1.com", "azureedge.net", "windows.net", "fastly.net", "cloudflare.net", "1e100.net",
                   "in-addr.arpa", "ip6.arpa", "local", "msftncsi.com", "trafficmanager.net")


@dataclass
class Finding:
    rule: str
    severity: str
    stage: str          # kill-chain stage used to order the attack story
    mitre: str          # MITRE ATT&CK technique
    title: str
    description: str
    hosts: list[str]
    first_seen: float
    last_seen: float
    evidence_frames: list[int] = field(default_factory=list)
    id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Thresholds:
    beacon_min_events: int = 6
    beacon_max_cv: float = 0.25        # interval jitter allowed (std / mean)
    beacon_min_interval: float = 5.0   # seconds; ignore tight bursts
    scan_min_ports: int = 15
    scan_min_hosts: int = 15
    dga_min_entropy: float = 3.3
    dga_min_length: int = 10
    nxdomain_min: int = 10
    exfil_min_bytes: int = 5_000_000
    exfil_min_ratio: float = 3.0
    brute_min_attempts: int = 20       # connections to one login service from one source
    brute_min_rate: float = 2.0        # attempts per minute
    tunnel_min_names: int = 30         # unique subdomains under one domain
    tunnel_min_avg_len: float = 20.0   # average subdomain length in characters
    lateral_min_hosts: int = 3         # internal hosts reached over remote-admin protocols

# Login services attackers guess passwords against
AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP", 389: "LDAP", 445: "SMB",
              1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM"}
# Remote-admin protocols used to move between machines
ADMIN_PORTS = {22: "SSH", 135: "RPC/WMI", 445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM"}


def _entropy(s: str) -> float:
    # Shannon entropy of a string; random names score high
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def _main_label(qname: str) -> str:
    # The label right before the TLD: "abc.evil.top" -> "evil"
    parts = qname.split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _spread(frames: list[int], n: int = 6) -> list[int]:
    # Keep a few evidence frames spread across the event (first, middle, last)
    if len(frames) <= n:
        return frames
    step = (len(frames) - 1) / (n - 1)
    return sorted({frames[round(i * step)] for i in range(n)})


def detect_cleartext_credentials(s: CaptureStore, t: Thresholds) -> list[Finding]:
    out = []
    for r in s.q("""SELECT src, dst, dport, service, indicator, MIN(ts) first_ts, MAX(ts) last_ts,
                    LIST(frame ORDER BY frame) frames FROM auth GROUP BY ALL"""):
        out.append(Finding(
            rule="cleartext_credentials", severity="high", stage="Credential Access", mitre="T1552 Unsecured Credentials",
            title=f"Credentials sent unencrypted over {r['service']}",
            description=f"{r['src']} sent login data ({r['indicator']}) in cleartext to {s.label(r['dst'])} port {r['dport']}. "
                        f"Anyone on the network path could read it.",
            hosts=[r["src"], r["dst"]], first_seen=r["first_ts"], last_seen=r["last_ts"], evidence_frames=_spread(r["frames"])))
    return out


def detect_suspicious_downloads(s: CaptureStore, t: Thresholds) -> list[Finding]:
    out = []
    for r in s.q("SELECT frame, ts, src, dst, method, uri, host, user_agent FROM http ORDER BY frame"):
        reasons = []
        path = r["uri"].split("?")[0].lower()
        if path.endswith(RISKY_EXTENSIONS):
            reasons.append(f"executable/script file ({path.rsplit('.', 1)[-1]})")
        ua = r["user_agent"].lower()
        if any(a in ua for a in RISKY_AGENTS):
            reasons.append(f"scripted client user-agent '{r['user_agent']}'")
        host = r["host"].split(":")[0]
        if host and host.replace(".", "").isdigit():
            reasons.append("request to a raw IP address instead of a domain")
        if not reasons or (len(reasons) == 1 and "user-agent" in reasons[0] and r["method"] != "GET"):
            continue
        sev = "critical" if len(reasons) >= 2 else "high"
        out.append(Finding(
            rule="suspicious_download", severity=sev, stage="Initial Access / Execution", mitre="T1105 Ingress Tool Transfer",
            title=f"Suspicious download by {r['src']}",
            description=f"{r['src']} requested http://{r['host']}{r['uri']} from {s.label(r['dst'])}: " + "; ".join(reasons) + ".",
            hosts=[r["src"], r["dst"]], first_seen=r["ts"], last_seen=r["ts"], evidence_frames=[r["frame"]]))
    return out


def detect_beaconing(s: CaptureStore, t: Thresholds) -> list[Finding]:
    # New outbound TCP connections (SYN) plus HTTP requests, grouped by source/destination
    rows = s.q("""SELECT frame, ts, src, dst, dport FROM packets
                  WHERE proto='TCP' AND flags='S' AND is_internal(src) AND NOT is_internal(dst)
                  UNION ALL SELECT frame, ts, src, dst, dport FROM http
                  WHERE is_internal(src) AND NOT is_internal(dst) ORDER BY ts""")
    groups: dict[tuple, list] = defaultdict(list)
    for r in rows:
        groups[(r["src"], r["dst"], r["dport"])].append((r["ts"], r["frame"]))
    out = []
    for (src, dst, dport), events in groups.items():
        times = sorted({round(ts, 3) for ts, _ in events})
        if len(times) < t.beacon_min_events:
            continue
        gaps = [b - a for a, b in zip(times, times[1:])]
        period = statistics.median(gaps)
        if period < t.beacon_min_interval:
            continue
        # Keep gaps near the typical period so one-off outliers (a big upload, a reboot) don't hide the pattern
        regular = [g for g in gaps if abs(g - period) <= t.beacon_max_cv * period]
        if len(regular) < max(t.beacon_min_events - 1, 0.75 * len(gaps)):
            continue
        jitter = statistics.pstdev(regular) / period
        frames = sorted(f for _, f in events)
        out.append(Finding(
            rule="beaconing", severity="high", stage="Command and Control", mitre="T1071 Application Layer Protocol",
            title=f"Regular beaconing from {src} to {s.label(dst)}",
            description=f"{src} contacted {s.label(dst)} on port {dport} {len(times)} times, about every {period:.0f}s "
                        f"(jitter {jitter:.0%}). Machine-regular check-ins like this are typical of malware calling its command server.",
            hosts=[src, dst], first_seen=times[0], last_seen=times[-1], evidence_frames=_spread(frames)))
    return out


def detect_port_scans(s: CaptureStore, t: Thresholds) -> list[Finding]:
    out = []
    # Vertical scan: one source probing many ports on one host
    for r in s.q("""SELECT src, dst, COUNT(DISTINCT dport) ports, MIN(ts) first_ts, MAX(ts) last_ts, LIST(frame ORDER BY frame) frames
                    FROM packets WHERE proto='TCP' AND flags='S' GROUP BY src, dst HAVING ports >= ?""", [t.scan_min_ports]):
        out.append(Finding(
            rule="port_scan", severity="medium", stage="Discovery", mitre="T1046 Network Service Discovery",
            title=f"Port scan of {r['dst']} by {r['src']}",
            description=f"{r['src']} probed {r['ports']} different ports on {s.label(r['dst'])} in "
                        f"{r['last_ts'] - r['first_ts']:.0f}s, looking for open services.",
            hosts=[r["src"], r["dst"]], first_seen=r["first_ts"], last_seen=r["last_ts"], evidence_frames=_spread(r["frames"])))
    # Horizontal sweep: one source probing the same port across many hosts
    for r in s.q("""SELECT src, dport, COUNT(DISTINCT dst) hosts, MIN(ts) first_ts, MAX(ts) last_ts, LIST(frame ORDER BY frame) frames
                    FROM packets WHERE proto='TCP' AND flags='S' GROUP BY src, dport HAVING hosts >= ?""", [t.scan_min_hosts]):
        out.append(Finding(
            rule="port_scan", severity="high" if is_internal(r["src"]) else "medium", stage="Discovery / Lateral Movement",
            mitre="T1046 Network Service Discovery",
            title=f"Network sweep on port {r['dport']} by {r['src']}",
            description=f"{r['src']} tried port {r['dport']} on {r['hosts']} different hosts in {r['last_ts'] - r['first_ts']:.0f}s. "
                        f"From an internal machine this often means an attacker or worm is looking for the next target.",
            hosts=[r["src"]], first_seen=r["first_ts"], last_seen=r["last_ts"], evidence_frames=_spread(r["frames"])))
    return out


def detect_suspicious_domains(s: CaptureStore, t: Thresholds) -> list[Finding]:
    out = []
    # Random-looking domain names (possible domain generation algorithm)
    flagged = defaultdict(list)
    for r in s.q("SELECT frame, ts, src, qname FROM dns WHERE NOT is_response ORDER BY frame"):
        q = r["qname"]
        if q.endswith(BENIGN_SUFFIXES):
            continue
        label = max(q.split(".")[:-1] or [q], key=len)
        if len(label) >= t.dga_min_length and _entropy(label) >= t.dga_min_entropy:
            flagged[r["src"]].append(r)
    for src, rows in flagged.items():
        names = sorted({r["qname"] for r in rows})
        out.append(Finding(
            rule="suspicious_domains", severity="medium" if len(names) < 3 else "high", stage="Command and Control",
            mitre="T1568.002 Domain Generation Algorithms",
            title=f"{src} looked up {len(names)} random-looking domain(s)",
            description=f"{src} queried high-randomness names such as {', '.join(names[:4])}. Malware often generates names like "
                        f"these to find its command server.",
            hosts=[src], first_seen=rows[0]["ts"], last_seen=rows[-1]["ts"], evidence_frames=_spread([r["frame"] for r in rows])))
    # Bursts of failed lookups (NXDOMAIN), another DGA signal
    for r in s.q("""SELECT dst AS host, COUNT(*) n, COUNT(DISTINCT qname) AS n_names, MIN(ts) first_ts, MAX(ts) last_ts,
                    LIST(frame ORDER BY frame) frames FROM dns WHERE is_response AND rcode='NXDOMAIN'
                    GROUP BY dst HAVING n >= ?""", [t.nxdomain_min]):
        out.append(Finding(
            rule="nxdomain_burst", severity="medium", stage="Command and Control", mitre="T1568.002 Domain Generation Algorithms",
            title=f"{r['host']} got {r['n']} failed DNS lookups",
            description=f"{r['host']} asked for {r['n_names']} domains that do not exist. Malware cycling through generated "
                        f"domains until one answers produces exactly this pattern.",
            hosts=[r["host"]], first_seen=r["first_ts"], last_seen=r["last_ts"], evidence_frames=_spread(r["frames"])))
    return out


def detect_exfiltration(s: CaptureStore, t: Thresholds) -> list[Finding]:
    out = []
    for r in s.q("""WITH flows AS (
                       SELECT CASE WHEN is_internal(src) THEN src ELSE dst END AS inside,
                              CASE WHEN is_internal(src) THEN dst ELSE src END AS outside,
                              SUM(CASE WHEN is_internal(src) THEN payload_len ELSE 0 END) AS sent,
                              SUM(CASE WHEN is_internal(src) THEN 0 ELSE payload_len END) AS received,
                       FROM packets WHERE is_internal(src) <> is_internal(dst) GROUP BY inside, outside)
                    SELECT * FROM flows WHERE sent >= ? AND sent >= ? * GREATEST(received, 1)""",
                 [t.exfil_min_bytes, t.exfil_min_ratio]):
        # Bulk of the upload = between 5% and 95% of cumulative bytes sent, so earlier small traffic doesn't skew the time
        ups = s.q("""SELECT frame, ts, payload_len FROM packets WHERE src=? AND dst=? AND payload_len > 0 ORDER BY ts""",
                  [r["inside"], r["outside"]])
        total, run, window = r["sent"], 0, []
        for u in ups:
            run += u["payload_len"]
            if 0.05 * total <= run <= 0.95 * total or not window and run > 0.05 * total:
                window.append(u)
        window = window or ups
        r["first_ts"], r["last_ts"], r["frames"] = window[0]["ts"], window[-1]["ts"], [u["frame"] for u in window]
        out.append(Finding(
            rule="data_exfiltration", severity="critical", stage="Exfiltration", mitre="T1041 Exfiltration Over C2 Channel",
            title=f"Large upload from {r['inside']} to {s.label(r['outside'])}",
            description=f"{r['inside']} sent {r['sent'] / 1e6:.1f} MB to {s.label(r['outside'])} but received only "
                        f"{r['received'] / 1e6:.2f} MB back. Uploads this lopsided to an outside server can mean stolen data.",
            hosts=[r["inside"], r["outside"]], first_seen=r["first_ts"], last_seen=r["last_ts"], evidence_frames=_spread(r["frames"] or [])))
    return out


def detect_brute_force(s: CaptureStore, t: Thresholds) -> list[Finding]:
    # Many new connections from one source to one login service = password guessing
    ports = list(AUTH_PORTS)
    out = []
    for r in s.q("""SELECT src, dst, dport, COUNT(*) n, MIN(ts) first_ts, MAX(ts) last_ts, LIST(frame ORDER BY frame) frames
                    FROM packets WHERE proto='TCP' AND flags='S' AND dport IN (SELECT UNNEST(?))
                    GROUP BY src, dst, dport HAVING n >= ?""", [ports, t.brute_min_attempts]):
        minutes = max((r["last_ts"] - r["first_ts"]) / 60, 1 / 60)
        rate = r["n"] / minutes
        if rate < t.brute_min_rate:
            continue
        svc = AUTH_PORTS[r["dport"]]
        out.append(Finding(
            rule="brute_force", severity="high", stage="Credential Access", mitre="T1110 Brute Force",
            title=f"{svc} brute force against {r['dst']} from {r['src']}",
            description=f"{s.label(r['src'])} opened {r['n']} {svc} connections to {s.label(r['dst'])} port {r['dport']} "
                        f"in {r['last_ts'] - r['first_ts']:.0f}s (about {rate:.0f} per minute). Rapid repeated logins like this "
                        f"usually mean someone is guessing passwords.",
            hosts=[r["src"], r["dst"]], first_seen=r["first_ts"], last_seen=r["last_ts"], evidence_frames=_spread(r["frames"])))
    return out


def detect_dns_tunneling(s: CaptureStore, t: Thresholds) -> list[Finding]:
    # Lots of long, unique subdomains under one domain = data smuggled inside DNS queries
    groups: dict[tuple, list] = defaultdict(list)
    for r in s.q("SELECT frame, ts, src, qname FROM dns WHERE NOT is_response ORDER BY frame"):
        q = r["qname"]
        parts = q.split(".")
        if len(parts) < 3 or q.endswith(BENIGN_SUFFIXES):
            continue
        groups[(r["src"], ".".join(parts[-2:]))].append((r, ".".join(parts[:-2])))
    out = []
    for (src, base), rows in groups.items():
        subs = {sub for _, sub in rows}
        avg_len = statistics.mean(len(x) for x in subs)
        if len(subs) < t.tunnel_min_names or avg_len < t.tunnel_min_avg_len:
            continue
        approx_bytes = sum(len(x) for x in subs) * 0.6  # rough payload after encoding overhead
        out.append(Finding(
            rule="dns_tunneling", severity="high", stage="Command and Control / Exfiltration",
            mitre="T1071.004 Application Layer Protocol: DNS",
            title=f"Possible DNS tunnel from {src} via {base}",
            description=f"{src} sent {len(rows)} queries for {len(subs)} unique subdomains of {base} (average {avg_len:.0f} "
                        f"characters, roughly {approx_bytes / 1000:.1f} KB of encoded data). Long, never-repeating names like "
                        f"these are how tools hide commands or stolen data inside DNS.",
            hosts=[src], first_seen=rows[0][0]["ts"], last_seen=rows[-1][0]["ts"],
            evidence_frames=_spread([r["frame"] for r, _ in rows])))
    return out


def detect_lateral_movement(s: CaptureStore, t: Thresholds) -> list[Finding]:
    # An internal host actually exchanging data with several other internal hosts over SMB/RDP/WinRM/SSH
    ports = list(ADMIN_PORTS)
    groups: dict[str, list] = defaultdict(list)
    for r in s.q("""SELECT frame, ts, src, dst, dport FROM packets
                    WHERE payload_len > 0 AND dport IN (SELECT UNNEST(?)) AND is_internal(src) AND is_internal(dst)
                    AND src <> dst ORDER BY ts""", [ports]):
        groups[r["src"]].append(r)
    out = []
    for src, rows in groups.items():
        targets = sorted({r["dst"] for r in rows})
        if len(targets) < t.lateral_min_hosts:
            continue
        protos = sorted({ADMIN_PORTS[r["dport"]] for r in rows})
        # One evidence frame per target so every hop is provable
        first_per_target = {}
        for r in rows:
            first_per_target.setdefault(r["dst"], r["frame"])
        out.append(Finding(
            rule="lateral_movement", severity="critical", stage="Lateral Movement", mitre="T1021 Remote Services",
            title=f"{src} used {'/'.join(protos)} on {len(targets)} internal hosts",
            description=f"{src} opened working {'/'.join(protos)} sessions to {len(targets)} other internal machines "
                        f"({', '.join(targets[:5])}{'...' if len(targets) > 5 else ''}). Hopping between machines with "
                        f"remote-admin tools is how attackers spread after the first compromise.",
            hosts=[src, *targets], first_seen=rows[0]["ts"], last_seen=rows[-1]["ts"],
            evidence_frames=_spread(sorted(first_per_target.values()), 8)))
    return out


DETECTORS = [detect_suspicious_downloads, detect_cleartext_credentials, detect_suspicious_domains,
             detect_beaconing, detect_port_scans, detect_exfiltration, detect_brute_force, detect_dns_tunneling,
             detect_lateral_movement]


def run_all(s: CaptureStore, t: Thresholds | None = None) -> list[Finding]:
    """Run every rule, sort by time, and give each finding a stable id (F1, F2, ...)."""
    t = t or Thresholds()
    findings = [f for det in DETECTORS for f in det(s, t)]
    findings.sort(key=lambda f: (f.first_seen, SEVERITY_ORDER[f.severity]))
    for i, f in enumerate(findings, start=1):
        f.id = f"F{i}"
    return findings
