"""Look and feel for the dashboard: theme CSS, risk score, kill-chain strip and rule coverage.

Everything here returns plain strings or numbers so it can be tested without Streamlit.
Only fixed labels, counts and escaped names go into HTML; capture-derived text never does.
"""
from __future__ import annotations

import html

# One palette shared with the charts and the project page
COLOR = {"critical": "#ff6b6b", "high": "#ffa657", "medium": "#e3b341", "low": "#8c97ad",
         "ok": "#3fb950", "accent": "#88cc14", "dim": "#2a3550"}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_WEIGHT = {"critical": 30, "high": 15, "medium": 6, "low": 2}

# (strip label, stage words that light it up). Finding stages can hold several, e.g. "Discovery / Lateral Movement"
KILL_CHAIN = [("Initial Access", ("Initial Access", "Execution")), ("Credential Access", ("Credential Access",)),
              ("Discovery", ("Discovery",)), ("Command & Control", ("Command and Control",)),
              ("Lateral Movement", ("Lateral Movement",)), ("Exfiltration", ("Exfiltration",))]

# (rule id, name, MITRE technique, one-line summary). Rule ids match Finding.rule
RULES = [
    ("suspicious_download", "Suspicious download", "T1105", "Executables or scripts over HTTP, scripted clients, raw-IP requests"),
    ("cleartext_credentials", "Cleartext credentials", "T1552", "Passwords sent unencrypted over HTTP, FTP, Telnet or mail"),
    ("suspicious_domains", "Random-looking domains", "T1568.002", "High-entropy names typical of domain generation"),
    ("nxdomain_burst", "Failed DNS lookup burst", "T1568.002", "Many lookups for domains that do not exist"),
    ("beaconing", "C2 beaconing", "T1071", "Outbound connections at machine-regular intervals"),
    ("port_scan", "Port scan or sweep", "T1046", "One host probing many ports, or one port on many hosts"),
    ("data_exfiltration", "Data exfiltration", "T1041", "Large, lopsided uploads to an outside server"),
    ("brute_force", "Brute force", "T1110", "Rapid repeated logins to SSH, RDP, SMB and similar services"),
    ("dns_tunneling", "DNS tunneling", "T1071.004", "Data hidden in long, unique DNS subdomains"),
    ("lateral_movement", "Lateral movement", "T1021", "One internal host working sessions on several others"),
]

RISK_BANDS = [(0, "Clean", COLOR["ok"]), (1, "Low", COLOR["accent"]), (25, "Elevated", COLOR["medium"]),
              (50, "High", COLOR["high"]), (75, "Critical", COLOR["critical"])]


def risk_score(findings) -> tuple[int, str, str]:
    """0-100 heuristic from finding severities (critical 30, high 15, medium 6, low 2, capped). Returns score, label, color."""
    score = min(100, sum(SEVERITY_WEIGHT[f.severity] for f in findings))
    label, color = next((lb, c) for floor, lb, c in reversed(RISK_BANDS) if score >= floor)
    return score, label, color


def kill_chain(findings) -> list[dict]:
    """For each kill-chain stage: how many findings hit it and the worst severity (None if untouched)."""
    out = []
    for name, words in KILL_CHAIN:
        hits = [f for f in findings if any(p.strip() in words for p in f.stage.split("/"))]
        worst = max((f.severity for f in hits), key=SEVERITY_RANK.get, default=None)
        out.append({"stage": name, "count": len(hits), "severity": worst})
    return out


def rule_coverage(findings) -> list[dict]:
    """Every rule with how many findings it produced and the worst severity (None = clear)."""
    out = []
    for rule, name, mitre, summary in RULES:
        hits = [f for f in findings if f.rule == rule]
        worst = max((f.severity for f in hits), key=SEVERITY_RANK.get, default=None)
        out.append({"rule": rule, "name": name, "mitre": mitre, "summary": summary, "count": len(hits), "severity": worst})
    return out


def risk_html(score: int, label: str, color: str, caption: str = "Risk score") -> str:
    return (f'<div class="th-card th-risk" style="--c:{color}"><div class="th-label">{html.escape(caption)}</div>'
            f'<div><span class="num" style="color:{color}">{score}</span><span class="of"> / 100</span></div>'
            f'<div class="verdict" style="color:{color}">{html.escape(label)}</div>'
            f'<div class="th-bar"><i style="width:{max(score, 3)}%;background:{color}"></i></div></div>')


def kill_chain_html(findings) -> str:
    cells = []
    for s in kill_chain(findings):
        color = COLOR[s["severity"]] if s["severity"] else COLOR["dim"]
        note = f'{s["count"]} finding{"s" if s["count"] != 1 else ""}' if s["count"] else "clear"
        cells.append(f'<div class="th-stage{" on" if s["count"] else ""}" style="--c:{color}">'
                     f'<b>{html.escape(s["stage"])}</b><span>{note}</span></div>')
    return '<div class="th-label">Kill chain</div><div class="th-chain">' + "".join(cells) + "</div>"


def coverage_html(findings) -> str:
    cards = []
    for r in rule_coverage(findings):
        color = COLOR[r["severity"]] if r["severity"] else COLOR["ok"]
        chip = f'{r["count"]} found' if r["count"] else "Clear"
        cards.append(f'<div class="th-rule" style="--c:{color}"><div><b>{html.escape(r["name"])}</b>'
                     f'<span class="mitre">{html.escape(r["mitre"])}</span><p>{html.escape(r["summary"])}</p></div>'
                     f'<span class="th-chip" style="--c:{color}">{chip}</span></div>')
    return '<div class="th-grid">' + "".join(cards) + "</div>"


def hosts_html(hosts) -> str:
    chips = "".join(f"<span>{html.escape(h)}</span>" for h in sorted(hosts)) or '<span>none yet</span>'
    return f'<div class="th-label">Hosts involved so far</div><div class="th-tags">{chips}</div>'


def title_html(title: str, meta: str) -> str:
    return f'<div class="th-title">{html.escape(title)}</div><div class="th-meta">{html.escape(meta)}</div>'


def sample_card_html(title: str, blurb: str, tags: list[str], size: str = "sample") -> str:
    chips = "".join(f"<span>{html.escape(t)}</span>" for t in tags)
    return (f'<div class="th-card th-{size}"><h4>{html.escape(title)}</h4><p>{html.escape(blurb)}</p>'
            f'<div class="th-tags">{chips}</div></div>')


CSS = """<style>
.block-container { padding-top: 2.2rem; max-width: 1240px; }
footer { visibility: hidden; }
[data-testid="stSidebar"] { border-right: 1px solid #2a3550; }
[data-testid="stMetric"] { background:#1a2236; border:1px solid #2a3550; border-radius:12px; padding:14px 18px; }
[data-testid="stMetricLabel"] p { color:#8c97ad; font-size:.74rem; font-weight:700; text-transform:uppercase; letter-spacing:.07em; }
[data-testid="stMetricValue"] { font-weight:800; }
[data-testid="stExpander"] { border:1px solid #2a3550; border-radius:12px; background:#12171e; }
button[data-baseweb="tab"] { font-weight:600; }
.stButton > button, .stDownloadButton > button { border-radius:8px; font-weight:600; }

.th-brand { font-size:1.4rem; font-weight:800; letter-spacing:-.3px; }
.th-brand i { color:#88cc14; font-style:normal; }
.th-tag { color:#8c97ad; font-size:.85rem; margin-bottom:.4rem; }
.th-label { color:#8c97ad; font-size:.7rem; font-weight:700; letter-spacing:.09em; text-transform:uppercase; margin:.2rem 0 .45rem; }
.th-title { font-size:1.9rem; font-weight:800; letter-spacing:-.5px; line-height:1.2; }
.th-meta { color:#8c97ad; font-size:.88rem; margin:.15rem 0 1rem; }

.th-hero h1 { font-size:2.7rem; letter-spacing:-1.2px; margin:0 0 .5rem; line-height:1.1; padding:0; }
.th-hero p { color:#8c97ad; font-size:1.1rem; max-width:780px; margin:0 0 1.4rem; }
.th-card { background:#1a2236; border:1px solid #2a3550; border-radius:14px; padding:18px 20px; }
.th-sample { min-height:215px; background:transparent; border:0; padding:6px 4px 0; }
[data-testid="stVerticalBlockBorderWrapper"]:has(.th-sample) { background:#1a2236; border:1px solid #2a3550; border-radius:14px; padding:8px 14px 14px; }
button[kind="primary"], button[kind="primary"] p { color:#0f1523 !important; font-weight:700; }
button[kind="primary"] { background:#88cc14; border-color:#88cc14; }
button[kind="primary"]:hover { background:#9be31a; border-color:#9be31a; }
.th-info { min-height:120px; }
.th-card h4 { margin:0 0 6px; font-size:1.05rem; padding:0; }
.th-card p { color:#8c97ad; font-size:.9rem; margin:0 0 12px; }
.th-tags span { display:inline-block; font:600 .68rem ui-monospace,Menlo,monospace; background:#0f1523; border:1px solid #2a3550;
  color:#8c97ad; border-radius:6px; padding:2px 7px; margin:0 4px 4px 0; }

.th-risk { border-top:3px solid var(--c); }
.th-risk .num { font-size:3.2rem; font-weight:800; line-height:1; }
.th-risk .of { color:#8c97ad; font-size:1rem; }
.th-risk .verdict { font-weight:800; letter-spacing:.06em; text-transform:uppercase; font-size:.85rem; margin-top:4px; }
.th-bar { height:6px; background:#2a3550; border-radius:4px; overflow:hidden; margin-top:12px; }
.th-bar i { display:block; height:100%; border-radius:4px; }

.th-chain { display:flex; gap:6px; margin-bottom:1.1rem; }
.th-stage { flex:1; min-width:0; border:1px solid #2a3550; background:#12171e; border-radius:10px; padding:10px 6px; text-align:center;
  display:flex; flex-direction:column; justify-content:center; }
.th-stage b { display:block; font-size:.74rem; line-height:1.25; color:#8c97ad; }
.th-stage span { font-size:.72rem; color:#6e7681; }
.th-stage.on { border-color:var(--c); background:color-mix(in srgb, var(--c) 14%, #12171e); }
.th-stage.on b { color:#e8edf5; }
.th-stage.on span { color:var(--c); font-weight:700; }

.th-grid { display:grid; grid-template-columns:repeat(2, 1fr); gap:12px; }
.th-rule { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; background:#1a2236;
  border:1px solid #2a3550; border-left:4px solid var(--c); border-radius:10px; padding:12px 14px; }
.th-rule b { font-size:.98rem; }
.th-rule .mitre { font:600 .72rem ui-monospace,Menlo,monospace; color:#8be9fd; margin-left:8px; }
.th-rule p { margin:4px 0 0; color:#8c97ad; font-size:.85rem; }
.th-chip { font-size:.72rem; font-weight:700; border-radius:999px; padding:2px 10px; white-space:nowrap; border:1px solid var(--c); color:var(--c); }

@media (max-width:820px) {
  .th-grid { grid-template-columns:1fr; } .th-chain { flex-wrap:wrap; } .th-stage { flex:1 1 30%; }
  .th-hero h1 { font-size:2rem; }
}
</style>"""
