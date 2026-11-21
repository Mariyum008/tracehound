"""Read Zeek logs (TSV or JSON, optionally .gz) into the same tables the pcap parser produces."""
from __future__ import annotations

import gzip
import ipaddress
import json
from pathlib import Path

from .parser import ParsedCapture

LOG_TYPES = ("conn", "dns", "http", "ssl", "ftp")
SYN_STATES = {"S0", "S1", "S2", "S3", "SF", "REJ", "RSTO", "RSTOS0", "RSTR", "SH"}  # states where a SYN was seen


def is_zeek_source(path: str) -> bool:
    """A folder containing conn.log, or a single Zeek log file."""
    p = Path(path)
    if p.is_dir():
        return any(_find(p, t) for t in ("conn", "dns", "http", "ssl"))
    name = p.name.lower()
    return any(name.startswith(t + ".") or name.startswith(t + "_") for t in LOG_TYPES) and (
        ".log" in name or name.endswith(".json"))


def _find(folder: Path, log_type: str) -> list[Path]:
    # Match conn.log, conn.log.gz, conn.json and rotated names like conn.09:00:00-10:00:00.log.gz
    return sorted(f for f in folder.iterdir() if f.is_file() and f.name.lower().startswith(log_type + ".")
                  and (".log" in f.name.lower() or f.name.lower().endswith(".json")))


def _open(path: Path):
    return gzip.open(path, "rt", errors="replace") if path.suffix == ".gz" else open(path, errors="replace")


def read_log(path: Path) -> list[dict]:
    """Rows of one Zeek log as dicts; handles both TSV (with #fields header) and JSON-per-line."""
    rows, fields, sep, unset, empty, set_sep = [], None, "\t", "-", "(empty)", ","
    with _open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("{"):  # JSON log: one object per line
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
                continue
            if line.startswith("#separator"):
                sep = line.split(" ", 1)[1].encode().decode("unicode_escape")  # e.g. "\x09" -> tab
                continue
            if line.startswith("#"):
                key, _, val = line[1:].partition(sep)
                if key == "fields":
                    fields = val.split(sep)
                elif key == "unset_field":
                    unset = val
                elif key == "empty_field":
                    empty = val
                elif key == "set_separator":
                    set_sep = val
                continue
            if fields is None:
                continue
            values = line.split(sep)
            row = {}
            for k, v in zip(fields, values):
                if v == unset:
                    row[k] = None
                elif v == empty:
                    row[k] = []
                elif k in ("answers", "TTLs", "tags"):
                    row[k] = v.split(set_sep)
                else:
                    row[k] = v
            rows.append(row)
    return rows


def _num(v, default=0):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _float(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _ts(v, fallback: float) -> float:
    # Zeek writes epoch seconds; JSON logs may use ISO strings; anything unreadable keeps file order
    try:
        return float(v)
    except (TypeError, ValueError):
        if isinstance(v, str) and "T" in v:
            from datetime import datetime
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
            except ValueError:
                pass
        return fallback


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def parse_zeek(path: str) -> ParsedCapture:
    """Turn Zeek logs into packet-like rows. Each row gets a record id (used where pcaps use frame numbers)."""
    p = Path(path)
    files = {t: (_find(p, t) if p.is_dir() else ([p] if p.name.lower().startswith(t + ".") else [])) for t in LOG_TYPES}
    events = []  # (ts, order, kind, row) so every table is filled in time order
    order = 0
    for log_type, paths in files.items():
        for f in paths:
            for row in read_log(f):
                order += 1
                events.append((_ts(row.get("ts"), order * 1e-3), order, log_type, row))
    events.sort(key=lambda e: (e[0], e[1]))

    cap = ParsedCapture(path=path, kind="zeek")
    rid = 0

    def new_id(log_type: str, row: dict) -> int:
        nonlocal rid
        rid += 1
        cap.refs[rid] = f"{log_type}.log uid={row.get('uid') or '-'}"
        return rid

    def marker(i: int, ts: float, a: str, b: str, proto: str, ap, bp) -> int:
        # Zero-byte packet row so every record can be cited and looked up as evidence (no effect on byte counts)
        cap.packets.append((i, ts, a, b, proto, ap, bp, "", 0, 0))
        return i

    for ts, _, log_type, r in events:
        src, dst = r.get("id.orig_h"), r.get("id.resp_h")
        if not src or not dst:
            continue
        sport, dport = _num(r.get("id.orig_p"), None), _num(r.get("id.resp_p"), None)

        if log_type == "conn":
            proto = (r.get("proto") or "").upper() or "OTHER"
            proto = proto if proto in ("TCP", "UDP") else "OTHER"
            history, state = r.get("history") or "", r.get("conn_state") or ""
            if proto == "TCP" and ("S" in history or (not history and state in SYN_STATES)):
                # The connection attempt itself (what scan and beacon detection look for)
                cap.packets.append((new_id("conn", r), ts, src, dst, "TCP", sport, dport, "S", 60, 0))
            mid = ts + _float(r.get("duration")) / 2  # place the bytes mid-connection for the traffic chart
            ob, rb = _num(r.get("orig_bytes")), _num(r.get("resp_bytes"))
            oib, rib = _num(r.get("orig_ip_bytes"), ob), _num(r.get("resp_ip_bytes"), rb)
            if ob or oib:
                cap.packets.append((new_id("conn", r), mid, src, dst, proto, sport, dport, "", oib or ob, ob))
            if rb or rib:
                cap.packets.append((new_id("conn", r), mid, dst, src, proto, dport, sport, "", rib or rb, rb))
            if proto == "UDP" and not (ob or rb or oib or rib):
                cap.packets.append((new_id("conn", r), ts, src, dst, "UDP", sport, dport, "", 0, 0))

        elif log_type == "dns" and r.get("query"):
            qname = str(r["query"]).rstrip(".").lower()
            proto = "TCP" if (r.get("proto") or "").lower() == "tcp" else "UDP"
            q = marker(new_id("dns", r), ts, src, dst, proto, sport, dport)
            cap.dns.append((q, ts, src, dst, qname, False, None, ""))
            rcode = r.get("rcode_name")
            if rcode:
                answers = [a for a in (r.get("answers") or []) if _is_ip(str(a))]
                a = marker(new_id("dns", r), ts + 1e-6, dst, src, proto, dport, sport)
                cap.dns.append((a, ts + 1e-6, dst, src, qname, True, rcode, ",".join(answers)))

        elif log_type == "http" and r.get("method"):
            host, ua = r.get("host") or "", r.get("user_agent") or ""
            h = marker(new_id("http", r), ts, src, dst, "TCP", sport, dport)
            cap.http.append((h, ts, src, dst, dport, r["method"], r.get("uri") or "/", host, ua))
            if r.get("username") or r.get("password"):
                cap.auth.append((h, ts, src, dst, dport, "HTTP", "HTTP Basic auth credentials logged by Zeek"))

        elif log_type == "ssl" and r.get("server_name"):
            t = marker(new_id("ssl", r), ts, src, dst, "TCP", sport, dport)
            cap.tls.append((t, ts, src, dst, dport, str(r["server_name"]).lower()))

        elif log_type == "ftp" and r.get("password") not in (None, "", "-"):
            # Zeek records the FTP password (or "<hidden>"); either way a cleartext login happened
            f = marker(new_id("ftp", r), ts, src, dst, "TCP", sport, dport)
            cap.auth.append((f, ts, src, dst, dport, "FTP", "FTP login logged by Zeek"))
    cap.packets.sort(key=lambda p: p[0])
    return cap
