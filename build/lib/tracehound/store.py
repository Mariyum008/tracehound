"""Load parsed tables into DuckDB so every question becomes a fast SQL query."""
from __future__ import annotations

import ipaddress
from functools import lru_cache

import duckdb
import pandas as pd

from .parser import ParsedCapture, parse_pcap

# Explicit column types so empty tables (e.g. no HTTP at all) still have the right schema
SCHEMAS = {
    "packets": {"frame": "BIGINT", "ts": "DOUBLE", "src": "VARCHAR", "dst": "VARCHAR", "proto": "VARCHAR",
                "sport": "INTEGER", "dport": "INTEGER", "flags": "VARCHAR", "length": "INTEGER", "payload_len": "INTEGER"},
    "dns": {"frame": "BIGINT", "ts": "DOUBLE", "src": "VARCHAR", "dst": "VARCHAR", "qname": "VARCHAR",
            "is_response": "BOOLEAN", "rcode": "VARCHAR", "answers": "VARCHAR"},
    "http": {"frame": "BIGINT", "ts": "DOUBLE", "src": "VARCHAR", "dst": "VARCHAR", "dport": "INTEGER", "method": "VARCHAR",
             "uri": "VARCHAR", "host": "VARCHAR", "user_agent": "VARCHAR"},
    "tls": {"frame": "BIGINT", "ts": "DOUBLE", "src": "VARCHAR", "dst": "VARCHAR", "dport": "INTEGER", "sni": "VARCHAR"},
    "auth": {"frame": "BIGINT", "ts": "DOUBLE", "src": "VARCHAR", "dst": "VARCHAR", "dport": "INTEGER",
             "service": "VARCHAR", "indicator": "VARCHAR"},
}


# Explicit "inside the network" ranges; ipaddress.is_private also covers reserved/documentation ranges, which is wrong here
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128")]


@lru_cache(maxsize=4096)
def is_internal(ip: str) -> bool:
    # RFC1918, carrier-grade NAT, loopback, link-local and IPv6 ULA count as internal
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in INTERNAL_NETS)
    except ValueError:
        return False


class CaptureStore:
    """One loaded capture: a DuckDB connection plus helpers used by detectors and tools."""

    def __init__(self, cap: ParsedCapture):
        self.path, self.kind, self.refs = cap.path, cap.kind, cap.refs
        self.con = duckdb.connect(":memory:")
        self.con.create_function("is_internal", is_internal, ["VARCHAR"], "BOOLEAN")
        for name, cols in SCHEMAS.items():
            ddl = ", ".join(f"{c} {typ}" for c, typ in cols.items())
            self.con.execute(f"CREATE TABLE {name} ({ddl})")
            rows = getattr(cap, name)
            if rows:
                df = pd.DataFrame(rows, columns=list(cols)).astype({"sport": "Int64", "dport": "Int64"} if name == "packets" else {})
                self.con.register(f"_{name}", df)
                self.con.execute(f"INSERT INTO {name} SELECT * FROM _{name}")
                self.con.unregister(f"_{name}")
        self.names = self._build_name_map()

    @classmethod
    def from_file(cls, path: str, max_packets: int | None = None) -> "CaptureStore":
        # Zeek log folders/files go through the Zeek reader; everything else is treated as a pcap
        from .zeek import is_zeek_source, parse_zeek
        return cls(parse_zeek(path) if is_zeek_source(path) else parse_pcap(path, max_packets))

    def q(self, sql: str, params: list | None = None) -> list[dict]:
        # Run SQL and return rows as dicts
        cur = self.con.execute(sql, params or [])
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def _build_name_map(self) -> dict[str, str]:
        # Map IPs to the domain names they were reached by (DNS answers, TLS SNI, HTTP Host)
        names: dict[str, str] = {}
        for r in self.q("SELECT qname, answers FROM dns WHERE is_response AND answers <> ''"):
            for ip in r["answers"].split(","):
                names.setdefault(ip, r["qname"])
        for r in self.q("SELECT DISTINCT dst, sni FROM tls"):
            names.setdefault(r["dst"], r["sni"])
        for r in self.q("SELECT DISTINCT dst, host FROM http WHERE host <> ''"):
            if r["host"].split(":")[0] != r["dst"]:
                names.setdefault(r["dst"], r["host"].split(":")[0])
        return names

    def label(self, ip: str) -> str:
        # "203.0.113.5 (evil.example)" when we know a name for the IP
        name = self.names.get(ip)
        return f"{ip} ({name})" if name else ip

    def describe_frames(self, frames: list[int]) -> list[dict]:
        """Human-readable summary of specific frames, used as evidence."""
        if not frames:
            return []
        frames = sorted(set(int(f) for f in frames))[:200]
        rows = {r["frame"]: r for r in self.q(
            "SELECT * FROM packets WHERE frame IN (SELECT UNNEST(?))", [frames])}
        extras: dict[int, list[str]] = {}
        for r in self.q("SELECT frame, qname, is_response, rcode, answers FROM dns WHERE frame IN (SELECT UNNEST(?))", [frames]):
            txt = f"DNS {'response' if r['is_response'] else 'query'} {r['qname']}"
            if r["is_response"]:
                txt += f" {r['rcode']}" + (f" -> {r['answers']}" if r["answers"] else "")
            extras.setdefault(r["frame"], []).append(txt)
        for r in self.q("SELECT frame, method, host, uri, user_agent FROM http WHERE frame IN (SELECT UNNEST(?))", [frames]):
            extras.setdefault(r["frame"], []).append(f"HTTP {r['method']} {r['host']}{r['uri']} UA='{r['user_agent']}'")
        for r in self.q("SELECT frame, sni FROM tls WHERE frame IN (SELECT UNNEST(?))", [frames]):
            extras.setdefault(r["frame"], []).append(f"TLS ClientHello SNI={r['sni']}")
        for r in self.q("SELECT frame, service, indicator FROM auth WHERE frame IN (SELECT UNNEST(?))", [frames]):
            extras.setdefault(r["frame"], []).append(f"CLEARTEXT {r['service']}: {r['indicator']}")
        out = []
        for f in frames:
            p = rows.get(f)
            if not p:
                out.append({"frame": f, "summary": "frame not found in capture"})
                continue
            ports = f":{p['sport']} -> " if p["sport"] is not None else " -> "
            dport = f":{p['dport']}" if p["dport"] is not None else ""
            summary = f"{p['proto']} {self.label(p['src'])}{ports}{self.label(p['dst'])}{dport}"
            if self.kind == "pcap" or p["length"]:  # Zeek record markers carry no byte count
                summary += f" len={p['length']}"
            if p["flags"]:
                summary += f" flags={p['flags']}"
            if f in extras:
                summary += " | " + "; ".join(extras[f])
            if f in self.refs:
                summary += f" [{self.refs[f]}]"  # the Zeek record this came from
            out.append({"frame": f, "time": p["ts"], "summary": summary})
        return out
