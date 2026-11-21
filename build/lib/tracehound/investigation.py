"""High-level investigation API shared by the CLI, the AI narrator and the MCP server."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .detectors import Finding, Thresholds, run_all, SEVERITY_ORDER
from .store import CaptureStore, is_internal

STAGE_ORDER = ["Discovery", "Initial Access / Execution", "Credential Access", "Command and Control",
               "Discovery / Lateral Movement", "Exfiltration"]


def fmt_time(ts: float | None) -> str:
    # UTC timestamp for reports
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "-"


class Investigation:
    def __init__(self, store: CaptureStore, thresholds: Thresholds | None = None):
        self.store = store
        self.findings: list[Finding] = run_all(store, thresholds)

    @classmethod
    def open(cls, path: str, max_packets: int | None = None) -> "Investigation":
        return cls(CaptureStore.from_file(path, max_packets))

    # ---- overview -------------------------------------------------------------
    def overview(self) -> dict:
        s = self.store
        base = s.q("SELECT COUNT(*) packets, MIN(ts) AS start_ts, MAX(ts) AS stop_ts, SUM(length) AS n_bytes FROM packets")[0]
        internal = [r["h"] for r in s.q("SELECT DISTINCT src AS h FROM packets WHERE is_internal(src) ORDER BY h")]
        talkers = s.q("""SELECT src, COUNT(*) packets, SUM(length) bytes FROM packets GROUP BY src
                         ORDER BY bytes DESC LIMIT 8""")
        protos = s.q("SELECT proto, COUNT(*) packets FROM packets GROUP BY proto ORDER BY packets DESC")
        sev = {}
        for f in self.findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        return {
            "file": s.path,
            "source": s.kind,  # "pcap" or "zeek"
            "packets": base["packets"],
            "bytes": int(base["n_bytes"] or 0),
            "start": fmt_time(base["start_ts"]),
            "end": fmt_time(base["stop_ts"]),
            "duration_seconds": round((base["stop_ts"] or 0) - (base["start_ts"] or 0), 1),
            "internal_hosts": internal,
            "top_talkers": [{"host": s.label(t["src"]), "packets": t["packets"], "bytes": int(t["bytes"])} for t in talkers],
            "protocols": {p["proto"]: p["packets"] for p in protos},
            "counts": {k: s.q(f"SELECT COUNT(*) n FROM {k}")[0]["n"] for k in ("dns", "http", "tls", "auth")},
            "findings_by_severity": sev,
        }

    # ---- findings and the attack story ----------------------------------------
    def findings_list(self, min_severity: str = "low") -> list[dict]:
        limit = SEVERITY_ORDER.get(min_severity, 3)
        return [f.to_dict() for f in self.findings if SEVERITY_ORDER[f.severity] <= limit]

    def patient_zero(self) -> str | None:
        # Earliest internal host involved in a high or critical finding
        for f in self.findings:
            if SEVERITY_ORDER[f.severity] <= 1:
                inside = [h for h in f.hosts if is_internal(h)]
                if inside:
                    return inside[0]
        return None

    def timeline(self) -> list[dict]:
        """Ordered attack story: each finding plus the DNS lookup that led to it, if any."""
        s, events = self.store, []
        for f in self.findings:
            outside = [h for h in f.hosts if not is_internal(h)]
            for ip in outside:
                name = s.names.get(ip)
                if not name:
                    continue
                look = s.q("""SELECT frame, ts, dst AS client FROM dns WHERE is_response AND qname=? AND answers LIKE ?
                              ORDER BY ts LIMIT 1""", [name, f"%{ip}%"])
                if look and look[0]["ts"] <= f.first_seen:
                    events.append({"time": look[0]["ts"], "kind": "context", "stage": f.stage,
                                   "text": f"{look[0]['client']} resolved {name} to {ip}", "frames": [look[0]["frame"]],
                                   "finding": f.id})
            events.append({"time": f.first_seen, "kind": "finding", "stage": f.stage, "severity": f.severity,
                           "text": f.title, "detail": f.description, "frames": f.evidence_frames, "finding": f.id,
                           "mitre": f.mitre})
        events.sort(key=lambda e: (e["time"], e["kind"] != "context"))
        # Drop duplicate context lines (same lookup supporting several findings)
        seen, ordered = set(), []
        for e in events:
            key = (e["kind"], e["text"])
            if key in seen:
                continue
            seen.add(key)
            e["time_utc"] = fmt_time(e["time"])
            ordered.append(e)
        return ordered

    # ---- pivots -----------------------------------------------------------------
    def host_profile(self, ip: str) -> dict:
        s = self.store
        base = s.q("""SELECT COUNT(*) packets, MIN(ts) first_ts, MAX(ts) last_ts,
                      SUM(CASE WHEN src=? THEN payload_len ELSE 0 END) sent,
                      SUM(CASE WHEN dst=? THEN payload_len ELSE 0 END) received
                      FROM packets WHERE src=? OR dst=?""", [ip, ip, ip, ip])[0]
        if not base["packets"]:
            return {"host": ip, "error": "host not seen in this capture"}
        peers = s.q("""SELECT dst peer, dport, COUNT(*) packets, SUM(payload_len) bytes, MIN(frame) first_frame
                       FROM packets WHERE src=? GROUP BY dst, dport ORDER BY bytes DESC LIMIT 15""", [ip])
        return {
            "host": s.label(ip),
            "internal": is_internal(ip),
            "packets": base["packets"],
            "first_seen": fmt_time(base["first_ts"]),
            "last_seen": fmt_time(base["last_ts"]),
            "bytes_sent": int(base["sent"] or 0),
            "bytes_received": int(base["received"] or 0),
            "top_destinations": [{"peer": s.label(p["peer"]), "port": p["dport"], "packets": p["packets"],
                                  "bytes": int(p["bytes"]), "first_frame": p["first_frame"]} for p in peers],
            "dns_queries": s.q("""SELECT qname, COUNT(*) times, MIN(frame) first_frame FROM dns
                                  WHERE src=? AND NOT is_response GROUP BY qname ORDER BY first_frame LIMIT 30""", [ip]),
            "http_requests": s.q("""SELECT frame, method, host, uri, user_agent FROM http WHERE src=? ORDER BY frame LIMIT 30""", [ip]),
            "tls_servers": s.q("""SELECT sni, dst, COUNT(*) times, MIN(frame) first_frame FROM tls WHERE src=?
                                  GROUP BY sni, dst ORDER BY first_frame LIMIT 30""", [ip]),
            "findings": [f.id + ": " + f.title for f in self.findings if ip in f.hosts],
        }

    def search(self, text: str, limit: int = 40) -> list[dict]:
        """Find frames whose IPs, domains, URLs, SNI or user-agents contain the text."""
        like = f"%{text.lower()}%"
        s = self.store
        hits = s.q(f"""
            SELECT frame, 'dns' kind, qname || ' ' || answers AS match FROM dns WHERE lower(qname || answers) LIKE ?
            UNION ALL SELECT frame, 'http', method || ' ' || host || uri || ' ' || user_agent FROM http
                WHERE lower(host || uri || user_agent || dst) LIKE ?
            UNION ALL SELECT frame, 'tls', sni || ' ' || dst FROM tls WHERE lower(sni || dst) LIKE ?
            ORDER BY frame LIMIT {int(limit)}""", [like, like, like])
        if not hits:
            hits = s.q(f"""SELECT frame, 'packet' kind, src || ' -> ' || dst AS match FROM packets
                           WHERE src LIKE ? OR dst LIKE ? ORDER BY frame LIMIT {int(limit)}""", [like, like])
        return hits

    def evidence(self, frames: list[int]) -> list[dict]:
        out = self.store.describe_frames(frames)
        for e in out:
            if "time" in e:
                e["time_utc"] = fmt_time(e.pop("time"))
        return out

    def verify_claim(self, frames: list[int], must_mention: list[str]) -> dict:
        """Check that cited frames actually contain the hosts/domains/strings a claim relies on."""
        ev = self.store.describe_frames(frames)
        missing_frames = [e["frame"] for e in ev if e["summary"] == "frame not found in capture"]
        text = " ".join(e["summary"].lower() for e in ev)
        results = {term: term.lower() in text for term in must_mention}
        return {
            "verified": bool(ev) and not missing_frames and all(results.values()),
            "terms": results,
            "missing_frames": missing_frames,
            "evidence": ev,
        }


CITE_RE = re.compile(r"\[frames?\s*([\d,\s]+)\]", re.I)


def check_citations(text: str, inv: Investigation) -> dict:
    """Find every [frame N] citation in AI-written text and confirm each frame exists and is part of the evidence."""
    cited = sorted({int(n) for m in CITE_RE.finditer(text) for n in re.findall(r"\d+", m.group(1))})
    known = {f for fd in inv.findings for f in fd.evidence_frames}
    known |= {f for e in inv.timeline() for f in e["frames"]}
    exists = {r["frame"] for r in inv.store.q("SELECT frame FROM packets WHERE frame IN (SELECT UNNEST(?))", [cited])} if cited else set()
    return {
        "cited_frames": cited,
        "nonexistent": [f for f in cited if f not in exists],
        "outside_evidence": [f for f in cited if f in exists and f not in known],
        "ok": bool(cited) and all(f in exists for f in cited),
    }
