"""Deterministic Markdown breach report (no AI needed)."""
from __future__ import annotations

from .investigation import Investigation, fmt_time

SEV_BADGE = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def markdown_report(inv: Investigation) -> str:
    ov = inv.overview()
    lines = [
        f"# Tracehound report - {ov['file']}",
        "",
        f"- **Capture window:** {ov['start']} to {ov['end']} ({ov['duration_seconds']}s, {ov['packets']} "
        f"{'Zeek records' if ov['source'] == 'zeek' else 'packets'})",
        f"- **Internal hosts:** {', '.join(ov['internal_hosts']) or 'none'}",
        f"- **Findings:** " + (", ".join(f"{n} {k}" for k, n in ov["findings_by_severity"].items()) or "none"),
    ]
    pz = inv.patient_zero()
    if pz:
        lines.append(f"- **Likely first compromised host:** {pz}")
    lines += ["", "## Attack timeline", ""]
    tl = inv.timeline()
    if not tl:
        lines.append("No suspicious activity detected.")
    for e in tl:
        frames = ", ".join(map(str, e["frames"]))
        if e["kind"] == "context":
            lines.append(f"- `{e['time_utc']}` - {e['text']} [frame {frames}]")
        else:
            lines.append(f"- `{e['time_utc']}` - **{SEV_BADGE[e['severity']]}** [{e['stage']}] {e['text']} "
                         f"({e['finding']}, {e['mitre']}) [frames {frames}]")
    lines += ["", "## Findings", ""]
    for f in inv.findings:
        lines += [
            f"### {f.id} - {f.title}",
            f"**Severity:** {SEV_BADGE[f.severity]} | **Stage:** {f.stage} | **MITRE ATT&CK:** {f.mitre}",
            "",
            f.description,
            "",
            f"Seen {fmt_time(f.first_seen)} to {fmt_time(f.last_seen)}. Evidence:",
            "",
        ]
        unit = "record" if ov["source"] == "zeek" else "frame"
        for ev in inv.evidence(f.evidence_frames):
            lines.append(f"- {unit} {ev['frame']}: `{ev['summary']}`")
        lines.append("")
    if ov["source"] == "zeek":
        lines += ["---", "Source: Zeek logs. Frame numbers are Tracehound record IDs; each evidence line names the Zeek log and uid."]
    else:
        lines += ["---", "Verify any frame in Wireshark with the display filter `frame.number == N`."]
    return "\n".join(lines)
