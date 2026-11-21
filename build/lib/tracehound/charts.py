"""Plotly figures for the dashboard. Colors: one blue for magnitude, status palette for severity."""
from __future__ import annotations

import math

import networkx as nx
import plotly.graph_objects as go

from .investigation import Investigation, STAGE_ORDER
from .store import is_internal

SERIES_BLUE = "#2a78d6"
MUTED = "#8a8984"
# Severity is a status, so it uses the reserved status palette and always ships with a text label
SEVERITY_COLOR = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "low": MUTED}
SEVERITY_ICON = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
BASE_LAYOUT = dict(margin=dict(l=10, r=10, t=40, b=10), hoverlabel=dict(font_size=13), font=dict(size=13))


def _style(fig: go.Figure, title: str, height: int = 360) -> go.Figure:
    # Shared layout: recessive grid, title names the single series so no legend is needed
    fig.update_layout(title=dict(text=title, x=0, font=dict(size=15)), height=height, **BASE_LAYOUT)
    fig.update_xaxes(showgrid=False, zeroline=False)
    fig.update_yaxes(gridcolor="rgba(128,128,128,0.18)", zeroline=False)
    return fig


def timeline_figure(inv: Investigation) -> go.Figure:
    """Findings placed by time (x) and attack stage (y), colored and labeled by severity."""
    events = [e for e in inv.timeline() if e["kind"] == "finding"]
    stages = [s for s in STAGE_ORDER if any(e["stage"] == s for e in events)]
    # Alternate label positions within a stage so close-together findings don't overlap
    pos_for, seen = {}, {}
    for e in events:
        k = seen.get(e["stage"], 0)
        pos_for[e["finding"]] = ("top center", "bottom center", "middle right", "middle left")[k % 4]
        seen[e["stage"]] = k + 1
    fig = go.Figure()
    for sev in ("critical", "high", "medium", "low"):
        rows = [e for e in events if e["severity"] == sev]
        if not rows:
            continue
        fig.add_trace(go.Scatter(
            x=[e["time_utc"].replace(" UTC", "") for e in rows], y=[e["stage"] for e in rows],
            mode="markers+text", name=SEVERITY_ICON[sev], text=[e["finding"] for e in rows],
            textposition=[pos_for[e["finding"]] for e in rows],
            marker=dict(size=16, color=SEVERITY_COLOR[sev], line=dict(width=2, color="white"),
                        symbol="triangle-up" if sev in ("critical", "high") else "circle"),
            customdata=[[e["text"], e["mitre"], ", ".join(map(str, e["frames"][:6]))] for e in rows],
            hovertemplate="<b>%{customdata[0]}</b><br>%{x} UTC<br>%{customdata[1]}<br>frames %{customdata[2]}<extra></extra>"))
    fig.update_yaxes(categoryorder="array", categoryarray=stages[::-1] if stages else None)
    fig.update_layout(legend=dict(orientation="h", y=-0.2))
    return _style(fig, "Attack timeline (by kill-chain stage)", height=120 + 60 * max(len(stages), 2))


def traffic_over_time(inv: Investigation) -> go.Figure:
    """Bytes per time bucket, with finding start times marked."""
    s = inv.store
    span = s.q("SELECT MIN(ts) AS a, MAX(ts) AS b FROM packets")[0]
    if span["a"] is None:
        return _style(go.Figure(), "Traffic over time")
    bucket = max(1, math.ceil((span["b"] - span["a"]) / 120))
    rows = s.q(f"""SELECT FLOOR((ts - ?) / {bucket}) AS k, SUM(length) AS n_bytes FROM packets GROUP BY k ORDER BY k""", [span["a"]])
    x = [r["k"] * bucket for r in rows]
    y = [r["n_bytes"] / 1000 for r in rows]
    fig = go.Figure(go.Scatter(x=x, y=y, mode="lines", line=dict(color=SERIES_BLUE, width=2), fill="tozeroy",
                               fillcolor="rgba(42,120,214,0.12)",
                               hovertemplate=f"t+%{{x}}s<br>%{{y:,.1f}} KB per {bucket}s<extra></extra>"))
    for f in inv.findings:
        if f.severity in ("critical", "high"):
            fig.add_vline(x=f.first_seen - span["a"], line=dict(color=SEVERITY_COLOR[f.severity], width=1, dash="dot"))
            fig.add_annotation(x=f.first_seen - span["a"], y=1, yref="paper", text=f.id, showarrow=False,
                               font=dict(size=11), yshift=8)
    fig.update_xaxes(title=f"seconds since capture start (dotted lines = high/critical findings)")
    fig.update_yaxes(title=f"KB per {bucket}s")
    fig.update_layout(hovermode="x unified")
    return _style(fig, "Traffic volume over time")


def top_talkers(inv: Investigation, n: int = 10) -> go.Figure:
    """Hosts sending the most bytes, as a sorted horizontal bar chart."""
    rows = inv.store.q(f"SELECT src, SUM(length) AS n_bytes FROM packets GROUP BY src ORDER BY n_bytes DESC LIMIT {int(n)}")[::-1]
    fig = go.Figure(go.Bar(x=[r["n_bytes"] / 1e6 for r in rows], y=[inv.store.label(r["src"]) for r in rows], orientation="h",
                           marker=dict(color=SERIES_BLUE, cornerradius=4), hovertemplate="%{y}<br>%{x:.2f} MB sent<extra></extra>"))
    fig.update_xaxes(title="MB sent")
    return _style(fig, "Top talkers (bytes sent)", height=110 + 32 * len(rows))


def protocol_mix(inv: Investigation) -> go.Figure:
    """Packets per application-level protocol we recognize."""
    s = inv.store
    counts = {k.upper(): s.q(f"SELECT COUNT(*) AS n FROM {k}")[0]["n"] for k in ("dns", "http", "tls")}
    for r in s.q("SELECT proto, COUNT(*) AS n FROM packets GROUP BY proto"):
        counts[f"All {r['proto']}"] = r["n"]
    items = sorted(((k, v) for k, v in counts.items() if v), key=lambda kv: kv[1])
    fig = go.Figure(go.Bar(x=[v for _, v in items], y=[k for k, _ in items], orientation="h",
                           marker=dict(color=SERIES_BLUE, cornerradius=4), hovertemplate="%{y}: %{x:,} packets<extra></extra>"))
    fig.update_xaxes(title="packets", type="log")
    return _style(fig, "Protocol mix (log scale)", height=110 + 32 * len(items))


def network_map(inv: Investigation, max_edges: int = 40, tiny_bytes: int = 1000) -> go.Figure:
    """Who talked to whom. Edge width = bytes; hosts in high/critical findings are red triangles with labels."""
    s = inv.store
    flagged = {h for f in inv.findings if f.severity in ("critical", "high") for h in f.hosts}
    edges = s.q(f"""SELECT LEAST(src, dst) AS a, GREATEST(src, dst) AS b, SUM(length) AS n_bytes FROM packets
                    GROUP BY a, b ORDER BY n_bytes DESC LIMIT {int(max_edges)}""")
    g = nx.Graph()
    for e in edges:
        g.add_edge(e["a"], e["b"], weight=e["n_bytes"])
    for f in inv.findings:  # every host in a finding stays on the map
        for h in f.hosts:
            g.add_node(h)
    # Collapse leaf hosts with almost no traffic (e.g. scan targets) into one cluster node per neighbor
    leaves = [n for n in list(g.nodes) if g.degree(n) == 1 and n not in flagged
              and next(iter(g[n].values())).get("weight", 0) < tiny_bytes]
    clusters: dict[str, list[str]] = {}
    for n in leaves:
        clusters.setdefault(next(iter(g[n])), []).append(n)
    cluster_names = {}
    for hub, members in clusters.items():
        if len(members) < 3:
            continue
        name = f"{len(members)} low-traffic hosts"
        cluster_names[name] = members
        g.remove_nodes_from(members)
        g.add_edge(hub, name, weight=sum(1 for _ in members) * 60)
    if not g.nodes:
        return _style(go.Figure(), "Host network map")
    try:  # unweighted: bytes are not distance; kamada-kawai needs scipy, so fall back if it is missing
        pos = nx.kamada_kawai_layout(g, weight=None) if len(g.nodes) > 2 else nx.spring_layout(g, seed=42)
    except ImportError:
        pos = nx.spring_layout(g, seed=42, weight=None, k=1.5 / math.sqrt(len(g.nodes)), iterations=200)
    fig = go.Figure()
    top = max((d.get("weight", 1) for _, _, d in g.edges(data=True)), default=1)
    for a, b, d in g.edges(data=True):
        hot = a in flagged and b in flagged
        fig.add_trace(go.Scatter(x=[pos[a][0], pos[b][0]], y=[pos[a][1], pos[b][1]], mode="lines", hoverinfo="skip",
                                 showlegend=False, line=dict(width=1.5 + 6 * d.get("weight", 1) / top,
                                                             color=SEVERITY_COLOR["critical"] if hot else "rgba(138,137,132,0.45)")))
    biggest = {n for n, _ in sorted(((n, sum(d["weight"] for d in g[n].values())) for n in g.nodes),
                                    key=lambda kv: -kv[1])[:6]}
    groups = {"External host": [], "Internal host": [], "Scan targets / low traffic": [], "In high/critical finding": []}
    for n in g.nodes:
        if n in flagged:
            groups["In high/critical finding"].append(n)
        elif n in cluster_names:
            groups["Scan targets / low traffic"].append(n)
        else:
            groups["Internal host" if is_internal(n) else "External host"].append(n)
    style = {"In high/critical finding": (SEVERITY_COLOR["critical"], "triangle-up", 22),
             "Internal host": (SERIES_BLUE, "circle", 14), "External host": (MUTED, "circle", 12),
             "Scan targets / low traffic": (SERIES_BLUE, "square-open", 18)}
    for name, nodes in groups.items():  # flagged group is drawn last so it sits on top
        if not nodes:
            continue
        color, symbol, size = style[name]
        labels = [n if n in cluster_names else s.label(n) for n in nodes]
        hover = [n + ": " + ", ".join(cluster_names[n][:8]) + ("..." if len(cluster_names[n]) > 8 else "")
                 if n in cluster_names else s.label(n) for n in nodes]
        fig.add_trace(go.Scatter(
            x=[pos[n][0] for n in nodes], y=[pos[n][1] for n in nodes], mode="markers+text", name=name,
            text=[lab if (n in flagged or n in biggest or n in cluster_names) else "" for n, lab in zip(nodes, labels)],
            textposition="bottom center", textfont=dict(size=12),
            marker=dict(size=size, color=color, symbol=symbol, line=dict(width=2, color="white")),
            customdata=hover, hovertemplate="%{customdata}<extra></extra>"))
    xs, ys = [p[0] for p in pos.values()], [p[1] for p in pos.values()]
    pad_x, pad_y = (max(xs) - min(xs)) * 0.18 + 0.1, (max(ys) - min(ys)) * 0.1 + 0.1
    fig.update_xaxes(visible=False, range=[min(xs) - pad_x, max(xs) + pad_x])  # room for labels at the edges
    fig.update_yaxes(visible=False, range=[min(ys) - pad_y, max(ys) + pad_y])
    fig.update_layout(legend=dict(orientation="h", y=-0.05))
    return _style(fig, "Host network map (line width = bytes exchanged; hover for details)", height=560)
