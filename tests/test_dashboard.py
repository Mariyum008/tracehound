"""Tests for the chat agent, Wireshark bridge, charts, Word export and the Streamlit dashboard."""
import copy
import io
import os
import stat
import sys
import types

import pytest
from docx import Document

from tracehound import charts, wireshark
from tracehound.agent import InvestigationAgent, run_tool
from tracehound.export import markdown_to_docx
from tracehound.investigation import Investigation
from tracehound.synthetic import C2_DOMAIN, VICTIM, write_breach_scenario


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    path = write_breach_scenario(str(tmp_path_factory.mktemp("cap") / "breach.pcap"))
    return path, Investigation.open(path)


def fake_client(script):
    """Anthropic stand-in: returns scripted responses in order and records every request."""
    calls = []

    class Messages:
        def create(self, **kw):
            calls.append(copy.deepcopy(kw))  # snapshot, since the agent keeps appending to the same list
            return script[len(calls) - 1](kw)

    return types.SimpleNamespace(messages=Messages()), calls


def text(t):
    return types.SimpleNamespace(type="text", text=t)


# --- chat agent -----------------------------------------------------------------

def test_agent_runs_tools_and_checks_citations(demo):
    _, inv = demo
    frame = inv.findings[0].evidence_frames[0]
    client, calls = fake_client([
        lambda kw: types.SimpleNamespace(stop_reason="tool_use", content=[
            types.SimpleNamespace(type="tool_use", id="a", name="investigate_host", input={"ip": VICTIM})]),
        lambda kw: types.SimpleNamespace(stop_reason="end_turn", content=[text(f"It downloaded a dropper [frame {frame}].")]),
    ])
    agent = InvestigationAgent(inv, client=client)
    seen = []
    res = agent.ask("What did the victim do?", on_tool=lambda n, a: seen.append(n))
    assert seen == ["investigate_host"] and res["citations"]["ok"]
    result = calls[1]["messages"][-1]["content"][0]
    assert result["type"] == "tool_result" and C2_DOMAIN in result["content"]
    assert calls[0]["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert len(agent.history) == 2  # tool chatter is not kept between questions


def test_agent_survives_tool_errors_and_flags_fake_frames(demo):
    _, inv = demo
    client, calls = fake_client([
        lambda kw: types.SimpleNamespace(stop_reason="tool_use", content=[
            types.SimpleNamespace(type="tool_use", id="a", name="investigate_host", input={})]),
        lambda kw: types.SimpleNamespace(stop_reason="end_turn", content=[text("Data left via [frame 999999].")]),
    ])
    res = InvestigationAgent(inv, client=client).ask("x")
    assert "error" in calls[1]["messages"][-1]["content"][0]["content"]
    assert res["citations"]["nonexistent"] == [999999]


def test_every_agent_tool_runs(demo):
    _, inv = demo
    frames = inv.findings[0].evidence_frames
    for name, args in [("find_threats", {}), ("build_timeline", {}), ("investigate_host", {"ip": VICTIM}),
                       ("search_capture", {"text": C2_DOMAIN}), ("get_evidence", {"frames": frames}),
                       ("verify_claim", {"frames": frames, "must_mention": [VICTIM]})]:
        assert run_tool(inv, name, args)


# --- Wireshark bridge (fake tshark/wireshark executables) -----------------------

@pytest.fixture
def fake_wireshark(tmp_path, monkeypatch):
    log = tmp_path / "calls.log"
    tshark = tmp_path / "tshark"
    tshark.write_text(f"""#!/bin/sh
echo "$@" >> {log}
if [ "$1" = "-D" ]; then echo "1. en0 (Wi-Fi)"; echo "2. lo0 (Loopback)"; exit 0; fi
while [ $# -gt 0 ]; do if [ "$1" = "-w" ]; then shift; touch "$1"; fi; shift; done
""")
    ws = tmp_path / "wireshark"
    ws.write_text(f"#!/bin/sh\necho \"$@\" >> {log}\n")
    for f in (tshark, ws):
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    return log


def test_interfaces_capture_and_open(fake_wireshark, tmp_path):
    assert wireshark.list_interfaces() == [{"id": "en0", "label": "en0 (Wi-Fi)"}, {"id": "lo0", "label": "lo0 (Loopback)"}]
    out = wireshark.capture("en0", 15, str(tmp_path / "live.pcapng"), bpf_filter="not port 22")
    assert os.path.isfile(out)
    wireshark.open_in_wireshark(out, frame=262, display_filter=wireshark.frame_filter([416, 262]))
    import time
    time.sleep(0.5)
    log = fake_wireshark.read_text()
    assert "-i en0 -a duration:15" in log and "-f not port 22" in log
    assert "-g 262 -Y frame.number in {262 416}" in log


def test_missing_wireshark_gives_clear_error(monkeypatch):
    monkeypatch.setattr(wireshark, "find_binary", lambda name: None)
    with pytest.raises(wireshark.WiresharkError, match="Install Wireshark"):
        wireshark.list_interfaces()


# --- charts and export ------------------------------------------------------------

def test_charts_build(demo):
    _, inv = demo
    for fn in (charts.timeline_figure, charts.traffic_over_time, charts.top_talkers, charts.protocol_mix, charts.network_map):
        assert fn(inv).data
    names = {t.name for t in charts.network_map(inv).data if t.name}
    assert "In high/critical finding" in names and "Scan targets / low traffic" in names


def test_markdown_to_docx():
    data = markdown_to_docx("# Summary\nThe host **192.168.1.20** was hit [frame 262].\n- one\n- `code`\n1. step", title="Report")
    doc = Document(io.BytesIO(data))
    body = [p.text for p in doc.paragraphs]
    assert "Summary" in body and any("192.168.1.20" in t for t in body) and "step" in body


# --- the dashboard itself -----------------------------------------------------------

def test_dashboard_renders_without_errors(demo, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("TRACEHOUND_HOME", str(tmp_path))
    app = os.path.join(os.path.dirname(charts.__file__), "dashboard.py")
    at = AppTest.from_file(app, default_timeout=120)
    at.session_state["pcap"] = demo[0]
    at.run()
    assert not at.exception
    assert [t.label for t in at.tabs] == ["Timeline", "Findings", "Traffic", "Network map", "Ask Claude", "Report"]
    assert len(at.get("plotly_chart")) == 5
    assert any("Wireshark" in b.label for b in at.button)


# --- live monitoring ------------------------------------------------------------------

@pytest.fixture
def streaming_tshark(tmp_path, monkeypatch, demo):
    # Fake tshark that streams the demo capture to stdout in chunks, or fails like macOS without ChmodBPF
    script = tmp_path / "tshark"
    script.write_text(f"""#!{sys.executable}
import os, sys, time
if "-D" in sys.argv: print("1. en0 (Wi-Fi)"); sys.exit(0)
if os.environ.get("FAKE_DENY"):
    sys.stderr.write("You don't have permission to capture on that device (/dev/bpf0: Permission denied)"); sys.exit(2)
data = open({demo[0]!r}, "rb").read()
step = len(data) // 3
for i in range(0, len(data), step):
    sys.stdout.buffer.write(data[i:i + step]); sys.stdout.buffer.flush(); time.sleep(0.5)
time.sleep(60)
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    return tmp_path


def test_live_monitor_grows_and_partial_snapshots_parse(streaming_tshark, demo):
    import time
    mon = wireshark.LiveMonitor("en0", str(streaming_tshark / "live.pcapng"))
    time.sleep(0.8)
    early = Investigation.open(mon.snapshot(str(streaming_tshark / "snap1.pcapng")))
    time.sleep(2.5)
    full = Investigation.open(mon.snapshot(str(streaming_tshark / "snap2.pcapng")))
    assert mon.running() and 0 < early.overview()["packets"] < full.overview()["packets"]
    assert len(full.findings) == len(demo[1].findings)  # once everything arrived, same result as the file
    mon.stop()
    assert not mon.running() and mon.error() is None  # user stop is not an error


def test_live_monitor_reports_permission_problem(streaming_tshark, monkeypatch):
    import time
    monkeypatch.setenv("FAKE_DENY", "1")
    mon = wireshark.LiveMonitor("en0", str(streaming_tshark / "denied.pcapng"))
    time.sleep(1)
    assert "Permission denied" in mon.error() and "ChmodBPF" in mon.error()


def test_empty_and_cut_off_captures(tmp_path, demo):
    from tracehound.parser import parse_pcap
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    assert parse_pcap(str(empty)).packets == []
    data = open(demo[0], "rb").read()
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(data[: len(data) // 2 + 37])
    assert 0 < len(parse_pcap(str(cut)).packets) < demo[1].overview()["packets"]


def test_network_map_without_scipy(demo, monkeypatch):
    monkeypatch.setitem(sys.modules, "scipy", None)
    assert charts.network_map(demo[1]).data
