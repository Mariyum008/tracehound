"""Tracehound dashboard. Run with: tracehound dashboard"""
from __future__ import annotations

import os
import time
from pathlib import Path

import streamlit as st

from tracehound import charts, ui, wireshark
from tracehound.agent import MODELS, InvestigationAgent
from tracehound.investigation import Investigation, fmt_time
from tracehound.report import markdown_report
from tracehound.store import is_internal

CAPTURE_DIR = Path(os.environ.get("TRACEHOUND_HOME", Path.home() / ".tracehound")) / "captures"
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
SEV_LABEL = {"critical": "\U0001F534 CRITICAL", "high": "\U0001F7E0 HIGH", "medium": "\U0001F7E1 MEDIUM", "low": "⚪ LOW"}

st.set_page_config(page_title="Tracehound", page_icon="\U0001F43E", layout="wide")
st.markdown(ui.CSS, unsafe_allow_html=True)

# Live capture and "Open in Wireshark" only make sense where Wireshark is installed (not on a hosted demo)
WS = wireshark.status()
LOCAL = bool(WS["tshark"] or WS["wireshark"])
SEV_BADGE = {"critical": ":red-badge[CRITICAL]", "high": ":orange-badge[HIGH]", "medium": ":yellow-badge[MEDIUM]",
             "low": ":gray-badge[LOW]"}

# One-click sample captures built from the same generators the tests use
SAMPLES = {
    "breach": dict(short="Breach", title="Breach: dropper to exfiltration", file="demo_breach.pcap", writer="write_breach_scenario",
                   blurb="A victim downloads a dropper, leaks a password, finds its C2 through random domains, beacons, "
                         "sweeps the network and uploads 6.3 MB.",
                   tags=["T1105", "T1552", "T1568.002", "T1071", "T1046", "T1041"]),
    "intrusion": dict(short="Intrusion", title="Intrusion: brute force to lateral movement", file="demo_intrusion.pcap",
                      writer="write_intrusion_scenario",
                      blurb="An SSH brute force against a server, a DNS tunnel out of it, then SMB, RDP and WinRM sessions "
                            "to four other machines.",
                      tags=["T1110", "T1071.004", "T1021"]),
    "clean": dict(short="Clean traffic", title="Clean traffic: nothing to find", file="demo_clean.pcap", writer="write_clean_scenario",
                  blurb="Normal browsing only. A good tool reports nothing here, which is the false-alarm check.",
                  tags=["0 findings expected"]),
}


@st.cache_resource(show_spinner=False, max_entries=4)
def load_investigation(path: str, mtime: float) -> Investigation:
    # Parse and analyze once per file version; mtime busts the cache when the file changes
    return Investigation.open(path)


@st.cache_data(ttl=60, show_spinner=False)
def interfaces() -> list[dict]:
    try:
        return wireshark.list_interfaces()
    except wireshark.WiresharkError:
        return []


def set_capture(path: str | None):
    # Switching captures resets the chat and any generated report
    st.session_state.update(pcap=path, chat=[], agent=None, ai_report=None, live_size=None, replay_step=0, playing=False)


def load_sample(name: str):
    from tracehound import synthetic
    spec = SAMPLES[name]
    set_capture(getattr(synthetic, spec["writer"])(str(CAPTURE_DIR / spec["file"])))


def open_frames(frames: list[int], key: str, label: str | None = None, show_filter: bool = True):
    """Button that opens Wireshark at the first frame with a filter showing all of them (a copyable filter if no Wireshark)."""
    frames = [int(f) for f in frames if f]
    if not frames:
        return
    refs = st.session_state.get("zeek_refs")
    if refs is not None:
        uids = sorted({refs[f].split("uid=")[-1] for f in frames if f in refs})
        st.caption("Zeek uid: " + ", ".join(f"`{u}`" for u in uids[:6]) + (" ..." if len(uids) > 6 else ""))
        return
    flt = wireshark.frame_filter(frames)
    if not LOCAL:
        if show_filter:
            st.caption("Wireshark display filter")
            st.code(flt, language=None)
        return
    label = label or (f"Open frame {frames[0]} in Wireshark" if len(frames) == 1 else f"Open these {len(frames)} frames in Wireshark")
    if st.button(label, key=key, icon=":material/open_in_new:"):
        try:
            wireshark.open_in_wireshark(st.session_state.pcap, frame=frames[0], display_filter=flt)
            st.toast("Opening Wireshark...")
        except wireshark.WiresharkError as e:
            st.warning(f"{e}\n\nIn Wireshark, paste this display filter: `{flt}`")


# ---------------------------------------------------------------- sidebar
st.session_state.setdefault("pcap", None)
st.session_state.setdefault("chat", [])
st.session_state.setdefault("agent", None)
st.session_state.setdefault("ai_report", None)

with st.sidebar:
    st.markdown('<div class="th-brand">\U0001F43E Trace<i>hound</i></div>'
                '<div class="th-tag">Breach investigation for packet captures</div>', unsafe_allow_html=True)

    st.markdown('<div class="th-label">1 &middot; Capture</div>', unsafe_allow_html=True)
    sources = ["Sample attacks", "Open a file", "Zeek logs"] + (["Live capture"] if LOCAL else [])
    source = st.radio("Source", sources, horizontal=True, label_visibility="collapsed")
    if not LOCAL and source != "Sample attacks":
        st.caption("Hosted demo: files are processed on a shared server. Please don't upload real or sensitive captures.")
    if source == "Open a file":
        up = st.file_uploader("Capture saved from Wireshark", type=["pcap", "pcapng", "cap"])
        if up is not None and st.button("Analyze file", type="primary", width="stretch"):
            dest = CAPTURE_DIR / up.name
            dest.write_bytes(up.getbuffer())
            set_capture(str(dest))
    elif source == "Zeek logs":
        st.caption("Upload conn.log plus any of dns.log, http.log, ssl.log, ftp.log (TSV or JSON, .gz is fine)."
                   + (" Or type the path to a Zeek log folder on this computer." if LOCAL else ""))
        logs = st.file_uploader("Zeek logs", accept_multiple_files=True, label_visibility="collapsed")
        folder = st.text_input("Zeek log folder", placeholder="/path/to/zeek/logs") if LOCAL else ""
        if st.button("Analyze Zeek logs", type="primary", width="stretch", disabled=not (logs or folder)):
            if logs:
                dest = CAPTURE_DIR / f"zeek_{time.strftime('%Y%m%d_%H%M%S')}"
                dest.mkdir(parents=True, exist_ok=True)
                for f in logs:
                    (dest / Path(f.name).name).write_bytes(f.getbuffer())
                set_capture(str(dest))
            elif Path(os.path.expanduser(folder)).is_dir():
                set_capture(os.path.expanduser(folder))
            else:
                st.error("That folder does not exist.")
        if st.button("Load demo breach as Zeek logs", width="stretch"):
            from tracehound.synthetic import write_zeek_breach
            set_capture(write_zeek_breach(str(CAPTURE_DIR / "demo_zeek")))
    elif source == "Live capture":
        ifaces = interfaces()
        mon = st.session_state.get("monitor")
        if not ifaces:
            st.warning("tshark was not found or cannot list interfaces. Install Wireshark, and on macOS run "
                       "'Install ChmodBPF.pkg' from the Wireshark disk image so it can capture without admin rights.")
        else:
            ids = [i["id"] for i in ifaces]
            iface = st.selectbox("Interface", ifaces, format_func=lambda i: i["label"],
                                 index=ids.index("en0") if "en0" in ids else 0, help="On a Mac, Wi-Fi is usually en0.")
            bpf = st.text_input("Capture filter (optional)", placeholder="e.g. not port 22")
            mode = st.radio("Mode", ["Live monitoring", "Fixed-length capture"], horizontal=True)
            if mode == "Live monitoring":
                st.session_state.refresh = st.select_slider("Refresh every (seconds)", [5, 10, 20, 30, 60], value=10)
                limit = st.number_input("Auto-stop after (minutes)", 1, 240, 30)
                if mon and mon.running():
                    if st.button("Stop monitoring", type="primary", width="stretch", icon=":material/stop_circle:"):
                        mon.stop()
                        st.session_state.pcap = mon.snapshot(str(CAPTURE_DIR / "live_snapshot.pcapng"))
                        st.rerun()
                elif st.button("Start live monitoring", type="primary", width="stretch", icon=":material/radio_button_checked:"):
                    if mon:
                        mon.stop()
                    out = CAPTURE_DIR / f"live_{iface['id'].replace('/', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.pcapng"
                    try:
                        mon = st.session_state.monitor = wireshark.LiveMonitor(iface["id"], str(out), bpf or None, int(limit) * 60)
                        time.sleep(2)  # give tshark a moment to fail fast on permission or interface errors
                        set_capture(None)
                        st.rerun()
                    except wireshark.WiresharkError as e:
                        st.error(str(e))
            else:
                secs = st.slider("Capture length (seconds)", 10, 300, 60, step=10)
                if st.button("Start capture", type="primary", width="stretch", icon=":material/radio_button_checked:"):
                    out = CAPTURE_DIR / f"capture_{iface['id'].replace('/', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.pcapng"
                    with st.spinner(f"Capturing on {iface['id']} for {secs}s... browse normally meanwhile"):
                        try:
                            wireshark.capture(iface["id"], secs, str(out), bpf or None)
                            set_capture(str(out))
                        except wireshark.WiresharkError as e:
                            st.error(str(e))
            if mon and mon.error():
                st.error("Capture stopped with an error:\n\n" + mon.error())
        st.caption("Only capture networks you own or are allowed to monitor.")
    else:
        for name, spec in SAMPLES.items():
            if st.button(spec["short"], key=f"side_{name}", width="stretch", help=spec["blurb"]):
                load_sample(name)

    st.markdown('<div class="th-label">2 &middot; Claude (optional)</div>', unsafe_allow_html=True)
    key = st.text_input("Anthropic API key", type="password", value=os.environ.get("ANTHROPIC_API_KEY", ""),
                        help="Only needed for the chat and AI report. Used for this session only. "
                             "Set ANTHROPIC_API_KEY to skip typing it.")
    model_name = st.selectbox("Model", list(MODELS), index=0)

    if LOCAL:
        st.markdown('<div class="th-label">3 &middot; Wireshark</div>', unsafe_allow_html=True)
        st.write(("\u2705" if WS["wireshark"] else "\u274c") + " Wireshark app  \n" + ("\u2705" if WS["tshark"] else "\u274c") + " tshark (live capture)")
        if st.session_state.pcap and Path(st.session_state.pcap).is_file() and WS["wireshark"] and \
                st.button("Open full capture in Wireshark", width="stretch"):
            wireshark.open_in_wireshark(st.session_state.pcap)
    else:
        st.caption("Live capture and Open in Wireshark are available when you run Tracehound on your own computer "
                   "with Wireshark installed.")
    st.markdown("---")
    st.caption("[GitHub](https://github.com/Mariyum008/tracehound) \u00b7 MIT licensed")

# ---------------------------------------------------------------- main
@st.fragment(run_every=st.session_state.get("refresh", 10))
def live_status():
    """While monitoring, snapshot the growing capture and re-run the analysis when new packets arrive."""
    mon = st.session_state.get("monitor")
    if not mon:
        return
    if mon.running():
        size = mon.size()
        st.info(f"\U0001F534 **LIVE** on `{mon.interface}` \u00B7 {int(time.time() - mon.started)}s \u00B7 "
                f"{size / 1000:,.0f} KB captured \u00B7 refreshes every {st.session_state.get('refresh', 10)}s")
        if size > 0 and size != st.session_state.get("live_size"):
            st.session_state.live_size = size
            st.session_state.pcap = mon.snapshot(str(CAPTURE_DIR / "live_snapshot.pcapng"))
            st.rerun(scope="app")
    elif mon.error() is None and st.session_state.get("live_size") != -1:
        # Auto-stopped normally: take a final snapshot once
        st.session_state.live_size = -1
        st.session_state.pcap = mon.snapshot(str(CAPTURE_DIR / "live_snapshot.pcapng"))
        st.rerun(scope="app")


live_status()

if not st.session_state.pcap:
    st.markdown('<div class="th-hero"><h1>Find the breach in the packets.</h1>'
                '<p>Tracehound reads a capture, flags the attack, builds the timeline and proves every claim with '
                'packet evidence. Pick a sample attack to see it work, or upload your own capture in the sidebar.</p></div>',
                unsafe_allow_html=True)
    cols = st.columns(len(SAMPLES), gap="medium")
    for col, (name, spec) in zip(cols, SAMPLES.items()):
        with col:
            st.markdown(ui.sample_card_html(spec["title"], spec["blurb"], spec["tags"]), unsafe_allow_html=True)
            if st.button(f"Analyze {spec['short'].lower()}", key=f"main_{name}", type="primary" if name == "breach" else "secondary",
                         width="stretch"):
                load_sample(name)
                st.rerun()
    st.markdown('<div class="th-label" style="margin-top:1.6rem">What you get</div>', unsafe_allow_html=True)
    a, b, c = st.columns(3, gap="medium")
    a.markdown(ui.sample_card_html("Findings with proof", "Ten detection rules, each mapped to MITRE ATT&CK and pointing at "
               "the exact frames that prove it.", [], "info"), unsafe_allow_html=True)
    b.markdown(ui.sample_card_html("Attack story", "A timeline across the kill chain, a network map and the likely first "
               "compromised host.", [], "info"), unsafe_allow_html=True)
    c.markdown(ui.sample_card_html("Ask Claude", "Chat about the capture. Every cited frame is checked against the "
               "evidence, and invented ones are flagged.", [], "info"), unsafe_allow_html=True)
    st.stop()

path = st.session_state.pcap
with st.spinner("Parsing packets and running detections..."):
    inv = load_investigation(path, os.path.getmtime(path))
ov = inv.overview()
st.session_state.zeek_refs = inv.store.refs if inv.store.kind == "zeek" else None
if not ov["packets"]:
    st.warning("No IP packets in this capture yet. If monitoring, browse a few sites and wait for the next refresh; "
               "otherwise check that you picked the right interface (Wi-Fi is usually en0 on a Mac).")
    st.stop()
sev = ov["findings_by_severity"]

title = next((sp["title"] for sp in SAMPLES.values() if sp["file"] == Path(path).name), Path(path).name)
st.markdown(ui.title_html(title, f"{ov['start']} to {ov['end']}  \u00b7  {ov['duration_seconds']}s  \u00b7  "
                                 f"{'Zeek logs' if ov['source'] == 'zeek' else 'packet capture'}"), unsafe_allow_html=True)
score, risk_label, risk_color = ui.risk_score(inv.findings)
left, right = st.columns([1, 3], gap="medium")
left.markdown(ui.risk_html(score, risk_label, risk_color), unsafe_allow_html=True)
with right:
    pz = inv.patient_zero()
    if pz:
        st.error(f"**Likely first compromised host: {pz}**. {len(inv.findings)} findings across the attack chain.", icon="\U0001F6A8")
    elif inv.findings:
        st.warning(f"{len(inv.findings)} lower-severity findings to review.")
    else:
        st.success("No suspicious activity detected by the current rules.")
    st.markdown(ui.kill_chain_html(inv.findings), unsafe_allow_html=True)
c = st.columns(6)
c[0].metric("Zeek records" if ov["source"] == "zeek" else "Packets", f"{ov['packets']:,}")
c[1].metric("Data", f"{ov['bytes'] / 1e6:.1f} MB")
c[2].metric("Internal hosts", len(ov["internal_hosts"]))
for col, sv in zip(c[3:], ("critical", "high", "medium")):
    col.metric(SEV_LABEL[sv], sev.get(sv, 0))

tab_tl, tab_replay, tab_find, tab_rules, tab_traffic, tab_map, tab_chat, tab_report = st.tabs(
    ["Timeline", "Replay", "Findings", "Detections", "Traffic", "Network map", "Ask Claude", "Report"])

with tab_tl:
    if inv.findings:
        st.plotly_chart(charts.timeline_figure(inv), width="stretch")
    for i, e in enumerate(inv.timeline()):
        with st.container(border=True):
            left, right = st.columns([5, 2])
            if e["kind"] == "context":
                left.markdown(f"`{e['time_utc']}` - {e['text']}")
            else:
                left.markdown(f"`{e['time_utc']}` {SEV_BADGE[e['severity']]} · {e['stage']} · {e['mitre']}  \n"
                              f"**{e['finding']}: {e['text']}**  \n{e['detail']}")
            with right:
                open_frames(e["frames"], key=f"tl{i}")

with tab_replay:
    evs = inv.findings  # already in time order
    n = len(evs)
    span = inv.store.q("SELECT MIN(ts) AS a, MAX(ts) AS b FROM packets")[0]
    if not n:
        st.info("Nothing to replay: no findings in this capture. Try one of the sample attacks.")
    else:
        st.caption("Scrub or play the attack as it unfolded. The risk score, kill chain and traffic chart show only what "
                   "had happened by that moment.")
        st.session_state.setdefault("replay_step", 0)
        st.session_state.setdefault("playing", False)
        st.session_state.replay_step = min(st.session_state.replay_step, n)

        def toggle_play():
            # Pressing play at the end starts over
            if not st.session_state.playing and st.session_state.replay_step >= n:
                st.session_state.replay_step = 0
            st.session_state.playing = not st.session_state.playing

        b1, b2, _ = st.columns([1, 1, 6])
        b1.button("Pause" if st.session_state.playing else "Play", key="replay_play", on_click=toggle_play, type="primary",
                  icon=":material/pause:" if st.session_state.playing else ":material/play_arrow:", width="stretch")
        b2.button("Restart", key="replay_restart", icon=":material/replay:", width="stretch",
                  on_click=lambda: st.session_state.update(replay_step=0, playing=False))

        # The timer lives in a fragment so only this part of the page refreshes on each tick
        @st.fragment(run_every=1.3 if st.session_state.playing else None)
        def replay():
            if st.session_state.playing:
                st.session_state.replay_step = min(st.session_state.replay_step + 1, n)
                if st.session_state.replay_step >= n:
                    st.session_state.playing = False
                    st.rerun()  # full rerun so the timer stops
            st.select_slider("Moment in the attack", options=list(range(n + 1)), key="replay_step",
                             format_func=lambda k: "Capture start" if k == 0 else f"{fmt_time(evs[k - 1].first_seen)[11:19]}  \u00b7  {evs[k - 1].id}")
            k = st.session_state.replay_step
            seen = evs[:k]
            now = span["a"] if k == 0 else evs[k - 1].first_seen
            r_score, r_label, r_color = ui.risk_score(seen)
            left, right = st.columns([1, 3], gap="medium")
            left.markdown(ui.risk_html(r_score, r_label, r_color, "Risk at this moment"), unsafe_allow_html=True)
            with right:
                st.markdown(ui.kill_chain_html(seen), unsafe_allow_html=True)
                st.markdown(ui.hosts_html({h for f in seen if f.severity in ("critical", "high") for h in f.hosts if is_internal(h)}),
                            unsafe_allow_html=True)
            if k:
                cur = evs[k - 1]
                with st.container(border=True):
                    st.markdown(f"`{fmt_time(cur.first_seen)}` {SEV_BADGE[cur.severity]} · {cur.stage} · {cur.mitre}  \n"
                                f"**{cur.id}: {cur.title}**  \n{cur.description}")
            else:
                st.info("Capture starts. Nothing suspicious has happened yet.")
            st.plotly_chart(charts.traffic_over_time(inv, until=now), width="stretch", key="replay_chart")
            if seen:
                st.markdown("**So far**")
                for f in seen:
                    st.markdown(f"{'**\u25b6**' if f is seen[-1] else '&nbsp;&nbsp;'} `{fmt_time(f.first_seen)[11:19]}` "
                                f"{SEV_BADGE[f.severity]} {f.id}: {f.title}")

        replay()

with tab_find:
    if not inv.findings:
        st.info("Nothing flagged. Try the demo breach to see what findings look like.")
    for f in inv.findings:
        with st.expander(f"{SEV_LABEL[f.severity]}  {f.id}: {f.title}", expanded=f.severity == "critical"):
            st.markdown(f"**Stage:** {f.stage}  ·  **MITRE ATT&CK:** {f.mitre}  \n"
                        f"**Seen:** {fmt_time(f.first_seen)} to {fmt_time(f.last_seen)}")
            st.write(f.description)
            ev = inv.evidence(f.evidence_frames)
            unit, what = ("record", "what the Zeek record shows") if ov["source"] == "zeek" else ("frame", "what the packet shows")
            st.dataframe([{unit: e["frame"], "time": e.get("time_utc", ""), what: e["summary"]} for e in ev],
                         hide_index=True, width="stretch")
            if ov["source"] != "zeek":
                st.code(wireshark.frame_filter(f.evidence_frames), language=None)
            open_frames(f.evidence_frames, key=f"find_{f.id}", show_filter=False)

with tab_rules:
    hit = sum(1 for r in ui.rule_coverage(inv.findings) if r["count"])
    st.caption(f"{hit} of {len(ui.RULES)} detection rules fired on this capture. Clear means the rule ran and found nothing.")
    st.markdown(ui.coverage_html(inv.findings), unsafe_allow_html=True)

with tab_traffic:
    st.plotly_chart(charts.traffic_over_time(inv), width="stretch")
    a, b = st.columns(2)
    a.plotly_chart(charts.top_talkers(inv), width="stretch")
    b.plotly_chart(charts.protocol_mix(inv), width="stretch")

with tab_map:
    st.plotly_chart(charts.network_map(inv), width="stretch")
    host = st.selectbox("Look at one host", [""] + ov["internal_hosts"], format_func=lambda h: h or "Choose a host")
    if host:
        prof = inv.host_profile(host)
        m = st.columns(3)
        m[0].metric("Sent", f"{prof['bytes_sent'] / 1e6:.2f} MB")
        m[1].metric("Received", f"{prof['bytes_received'] / 1e6:.2f} MB")
        m[2].metric("Findings", len(prof["findings"]))
        for line in prof["findings"]:
            st.write("- " + line)
        st.dataframe(prof["top_destinations"], hide_index=True, width="stretch")

with tab_chat:
    if not key:
        st.info("Add your Anthropic API key in the sidebar to chat with Claude about this capture.")
    else:
        agent = st.session_state.agent
        if agent is None or agent.model != MODELS[model_name] or agent.inv is not inv:
            history = agent.history if agent else []
            agent = st.session_state.agent = InvestigationAgent(inv, model=MODELS[model_name], api_key=key)
            agent.history = history  # live refreshes and model switches keep the conversation
        if not st.session_state.chat:
            st.caption("Try: *What happened here, step by step?* · *How did the attacker get in?* · "
                       "*Was any data stolen? Prove it.* · *What should I filter on in Wireshark to see the C2 traffic?*")
        for n, msg in enumerate(st.session_state.chat):
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])
                if msg.get("tools"):
                    with st.expander(f"{len(msg['tools'])} tool calls"):
                        for t in msg["tools"]:
                            st.code(f"{t['tool']}({t['input']})", language=None)
                cit = msg.get("citations")
                if cit and cit["cited_frames"]:
                    if cit["nonexistent"]:
                        st.warning(f"Claude cited frames that are not in this capture: {cit['nonexistent']}. Treat those claims as unverified.")
                    real = [f for f in cit["cited_frames"] if f not in cit["nonexistent"]]
                    if real:
                        open_frames(real, key=f"chat{n}", label=f"Open the {len(real)} cited frame(s) in Wireshark")
        question = st.chat_input("Ask about this capture...")
        if question:
            st.session_state.chat.append({"role": "user", "content": question})
            with st.status("Claude is investigating...", expanded=False) as status:
                try:
                    res = agent.ask(question, on_tool=lambda name, args: status.write(f"Calling `{name}`"))
                    st.session_state.chat.append({"role": "assistant", "content": res["text"], "tools": res["tool_calls"],
                                                  "citations": res["citations"]})
                    status.update(label="Done", state="complete")
                except Exception as e:
                    st.session_state.chat.pop()
                    status.update(label="Claude request failed", state="error")
                    st.error(f"{type(e).__name__}: {e}")
                    st.stop()
            st.rerun()

with tab_report:
    st.write("Export the investigation as an editable Word document or Markdown.")
    base = Path(path).stem
    rule_md = markdown_report(inv)
    a, b = st.columns(2)
    with a:
        st.markdown("**Evidence report** (no AI)")
        from tracehound.export import markdown_to_docx
        st.download_button("Download Word (.docx)", markdown_to_docx(rule_md), f"{base}_evidence_report.docx", key="dl_rule_docx")
        st.download_button("Download Markdown", rule_md, f"{base}_evidence_report.md", key="dl_rule_md")
    with b:
        st.markdown("**AI incident report** (Claude)")
        if st.button("Generate with Claude", disabled=not key or not inv.findings, type="primary"):
            from tracehound.narrator import narrate
            with st.spinner("Claude is writing the incident report..."):
                try:
                    st.session_state.ai_report = narrate(inv, model=MODELS[model_name], api_key=key)
                except Exception as e:
                    st.error(f"{type(e).__name__}: {e}")
        rep = st.session_state.ai_report
        if rep:
            c = rep["citations"]
            note = (f"\n\n---\n*Citation check: {len(c['cited_frames'])} frames cited, {len(c['nonexistent'])} not in the capture.*")
            text = rep["narrative"] + note
            st.download_button("Download Word (.docx)", markdown_to_docx(text, title=f"Incident report - {base}"),
                               f"{base}_incident_report.docx", key="dl_ai_docx")
            st.download_button("Download Markdown", text, f"{base}_incident_report.md", key="dl_ai_md")
    if st.session_state.ai_report:
        st.divider()
        st.markdown(st.session_state.ai_report["narrative"])
    else:
        with st.expander("Preview the evidence report"):
            st.markdown(rule_md)
