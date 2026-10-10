"""Evaluation harness: score Tracehound against breach captures with known answers."""
from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .investigation import Investigation
from .store import is_internal

CAPTURE_EXT = (".pcap", ".pcapng", ".cap")
TEMPLATE = {
    "name": "2026-01-15 exercise (rename me)",
    "source_url": "https://www.malware-traffic-analysis.net/...",
    "infected_hosts": ["10.0.0.0"],
    "iocs": {"ips": ["203.0.113.1"], "domains": ["bad.example"]},
    "notes": "Copy these from the exercise's answers page. Leave a list empty if the answers do not give it.",
}


@dataclass
class CaseResult:
    case: str
    capture: str
    packets: int = 0
    seconds: float = 0.0
    findings: int = 0
    patient_zero: str | None = None
    patient_zero_correct: bool = False
    hosts_found: list[str] = field(default_factory=list)
    hosts_missed: list[str] = field(default_factory=list)
    extra_hosts_flagged: list[str] = field(default_factory=list)
    iocs_found: list[str] = field(default_factory=list)
    iocs_missed: list[str] = field(default_factory=list)
    rules_fired: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def host_recall(self) -> float | None:
        total = len(self.hosts_found) + len(self.hosts_missed)
        return len(self.hosts_found) / total if total else None

    @property
    def host_precision(self) -> float | None:
        total = len(self.hosts_found) + len(self.extra_hosts_flagged)
        return len(self.hosts_found) / total if total else None

    @property
    def ioc_recall(self) -> float | None:
        total = len(self.iocs_found) + len(self.iocs_missed)
        return len(self.iocs_found) / total if total else None


def find_cases(folder: str) -> list[tuple[Path, Path]]:
    """Each case is a capture plus an answer key named <capture>.answers.json (or answers.json in its own folder)."""
    from .zeek import is_zeek_source
    cases = []
    # Zeek cases: a folder of logs with answers.json beside them
    for key in sorted(Path(folder).rglob("answers.json")):
        if is_zeek_source(str(key.parent)) and not any(p.suffix.lower() in CAPTURE_EXT for p in key.parent.iterdir()):
            cases.append((key.parent, key))
    for cap in sorted(p for p in Path(folder).rglob("*") if p.suffix.lower() in CAPTURE_EXT):
        key = cap.with_name(cap.name + ".answers.json")
        if not key.exists():
            key = cap.parent / "answers.json"
        if key.exists():
            cases.append((cap, key))
    return cases


def score_case(capture: Path, key_path: Path) -> CaseResult:
    """Run the full pipeline on one capture and compare against its answer key."""
    key = json.loads(key_path.read_text())
    res = CaseResult(case=key.get("name", capture.stem), capture=str(capture))
    t0 = time.time()
    try:
        inv = Investigation.open(str(capture))
    except Exception as e:  # a broken capture should not stop the whole run
        res.error = f"{type(e).__name__}: {e}"
        return res
    res.seconds = round(time.time() - t0, 2)
    res.packets = inv.overview()["packets"]
    res.findings = len(inv.findings)
    res.rules_fired = sorted({f.rule for f in inv.findings})

    # Hosts: internal machines named in high/critical findings vs the known infected ones
    truth = set(key.get("infected_hosts", []))
    # The accused host of a finding is its first internal host (the one doing it, not e.g. the server it talked to)
    flagged = set()
    for f in inv.findings:
        if f.severity in ("critical", "high"):
            actor = next((h for h in f.hosts if is_internal(h)), None)
            if actor:
                flagged.add(actor)
    res.patient_zero = inv.patient_zero()
    # On a clean capture, flagging nobody is the correct answer
    res.patient_zero_correct = res.patient_zero in truth if truth else res.patient_zero is None
    res.hosts_found = sorted(truth & flagged)
    res.hosts_missed = sorted(truth - flagged)
    res.extra_hosts_flagged = sorted(flagged - truth)

    # IOCs: an indicator counts as found if any finding, its evidence, or a mapped name mentions it
    blob = " ".join(f"{f.title} {f.description} {' '.join(f.hosts)}" for f in inv.findings).lower()
    blob += " " + " ".join(e["summary"].lower() for f in inv.findings for e in inv.evidence(f.evidence_frames))
    blob += " " + " ".join(inv.store.names.get(h, "") for f in inv.findings for h in f.hosts).lower()
    iocs = key.get("iocs", {})
    for ioc in [*iocs.get("ips", []), *iocs.get("domains", [])]:
        (res.iocs_found if ioc.lower() in blob else res.iocs_missed).append(ioc)
    return res


def _pct(x: float | None) -> str:
    return "-" if x is None else f"{x:.0%}"


def summarize(results: list[CaseResult]) -> dict:
    ok = [r for r in results if not r.error]

    def micro(found, missed):
        f, m = sum(len(getattr(r, found)) for r in ok), sum(len(getattr(r, missed)) for r in ok)
        return f / (f + m) if f + m else None

    return {
        "cases": len(results),
        "errors": len(results) - len(ok),
        "patient_zero_accuracy": sum(r.patient_zero_correct for r in ok) / len(ok) if ok else None,
        "infected_host_recall": micro("hosts_found", "hosts_missed"),
        "infected_host_precision": micro("hosts_found", "extra_hosts_flagged"),
        "ioc_recall": micro("iocs_found", "iocs_missed"),
        "avg_seconds": round(sum(r.seconds for r in ok) / len(ok), 2) if ok else None,
        "clean_cases": sum(1 for r in ok if not r.hosts_found and not r.hosts_missed),
        "clean_cases_with_alerts": sum(1 for r in ok if not r.hosts_found and not r.hosts_missed and r.extra_hosts_flagged),
    }


def markdown(results: list[CaseResult], summary: dict) -> str:
    lines = [
        "# Tracehound evaluation", "",
        f"**{summary['cases']} cases** ({summary['errors']} failed to load)", "",
        "| Metric | Score |", "|---|---|",
        f"| First infected host correct | {_pct(summary['patient_zero_accuracy'])} |",
        f"| Infected hosts found (recall) | {_pct(summary['infected_host_recall'])} |",
        f"| Flagged hosts that were really infected (precision) | {_pct(summary['infected_host_precision'])} |",
        f"| Indicators of compromise found (recall) | {_pct(summary['ioc_recall'])} |",
        f"| Clean captures with false alarms | {summary['clean_cases_with_alerts']} of {summary['clean_cases']} |",
        f"| Average analysis time | {summary['avg_seconds']}s |", "",
        "## Per case", "",
        "| Case | Packets | First host | Host recall | IOC recall | Rules fired |", "|---|---|---|---|---|---|",
    ]
    for r in results:
        if r.error:
            lines.append(f"| {r.case} | - | error: {r.error} | - | - | - |")
            continue
        pz = f"{'yes' if r.patient_zero_correct else 'no'} ({r.patient_zero or 'none'})"
        lines.append(f"| {r.case} | {r.packets:,} | {pz} | {_pct(r.host_recall)} | {_pct(r.ioc_recall)} | "
                     f"{', '.join(r.rules_fired) or 'none'} |")
    misses = [r for r in results if not r.error and (r.hosts_missed or r.iocs_missed)]
    if misses:
        lines += ["", "## What was missed (use this to improve the detection rules)", ""]
        for r in misses:
            lines.append(f"- **{r.case}**: " + "; ".join(filter(None, [
                f"hosts {', '.join(r.hosts_missed)}" if r.hosts_missed else "",
                f"indicators {', '.join(r.iocs_missed)}" if r.iocs_missed else ""])))
    return "\n".join(lines) + "\n"


def run(folder: str, out_dir: str | None = None) -> tuple[list[CaseResult], dict]:
    """Score every case in the folder and write results.md, results.json and results.csv."""
    cases = find_cases(folder)
    results = [score_case(cap, key) for cap, key in cases]
    summary = summarize(results)
    out = Path(out_dir or folder)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.md").write_text(markdown(results, summary))
    rows = [{**asdict(r), "host_recall": r.host_recall, "host_precision": r.host_precision, "ioc_recall": r.ioc_recall}
            for r in results]
    (out / "results.json").write_text(json.dumps({"summary": summary, "cases": rows}, indent=2))
    with open(out / "results.csv", "w", newline="") as fh:
        flat = [{k: "; ".join(v) if isinstance(v, list) else v for k, v in row.items()} for row in rows]
        if flat:
            w = csv.DictWriter(fh, fieldnames=list(flat[0]))
            w.writeheader()
            w.writerows(flat)
    return results, summary


def write_demo_cases(folder: str) -> str:
    """Two ready-made cases (breach + clean) so the harness can be tried without downloading anything."""
    from .synthetic import C2_DOMAIN, C2_IP, DROPPER_IP, VICTIM, write_breach_scenario, write_clean_scenario
    root = Path(folder)
    (root / "demo-breach").mkdir(parents=True, exist_ok=True)
    (root / "demo-clean").mkdir(parents=True, exist_ok=True)
    write_breach_scenario(str(root / "demo-breach" / "capture.pcap"))
    (root / "demo-breach" / "answers.json").write_text(json.dumps({
        "name": "Synthetic breach", "infected_hosts": [VICTIM],
        "iocs": {"ips": [DROPPER_IP, C2_IP], "domains": [C2_DOMAIN]}}, indent=2))
    write_clean_scenario(str(root / "demo-clean" / "capture.pcap"))
    (root / "demo-clean" / "answers.json").write_text(json.dumps({
        "name": "Clean browsing (should flag nothing)", "infected_hosts": [], "iocs": {"ips": [], "domains": []}}, indent=2))
    return str(root)
