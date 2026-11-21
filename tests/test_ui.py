"""Dashboard look-and-feel helpers, the stage order fix, and the one-click sample attacks."""
import os

import pytest

from tracehound import charts, ui
from tracehound.investigation import STAGE_ORDER, Investigation
from tracehound.synthetic import write_breach_scenario, write_clean_scenario, write_intrusion_scenario


@pytest.fixture(scope="module")
def cases(tmp_path_factory):
    d = tmp_path_factory.mktemp("ui")
    return {n: Investigation.open(w(str(d / f"{n}.pcap"))) for n, w in
            (("breach", write_breach_scenario), ("intrusion", write_intrusion_scenario), ("clean", write_clean_scenario))}


def test_risk_score_bands(cases):
    assert ui.risk_score(cases["clean"].findings)[:2] == (0, "Clean")
    assert ui.risk_score(cases["breach"].findings)[:2] == (100, "Critical")
    score, label, _ = ui.risk_score(cases["intrusion"].findings)
    assert 75 <= score < 100 and label == "Critical"


def test_kill_chain_lights_the_right_stages(cases):
    lit = lambda inv: {s["stage"] for s in ui.kill_chain(inv.findings) if s["count"]}
    assert lit(cases["clean"]) == set()
    assert lit(cases["breach"]) == {n for n, _ in ui.KILL_CHAIN}
    assert lit(cases["intrusion"]) == {"Credential Access", "Command & Control", "Lateral Movement", "Exfiltration"}


def test_every_rule_is_listed_and_coverage_matches(cases):
    fired = {f.rule for inv in cases.values() for f in inv.findings}
    assert fired == {r[0] for r in ui.RULES}  # all 10 rules fire somewhere and none is missing from the panel
    cov = {r["rule"]: r["count"] for r in ui.rule_coverage(cases["intrusion"].findings)}
    assert cov["brute_force"] == cov["dns_tunneling"] == cov["lateral_movement"] == 1 and cov["data_exfiltration"] == 0


def test_html_escapes_names():
    assert "<script>" not in ui.title_html("<script>alert(1)</script>", "x") and "&lt;script&gt;" in ui.title_html("<script>", "x")
    assert "<b>" not in ui.sample_card_html("<b>t</b>", "b", ["<i>"]).replace("<b>t", "").replace("</b>", "")


def test_new_stages_are_ordered_on_the_timeline(cases):
    stages = {f.stage for inv in cases.values() for f in inv.findings}
    assert stages <= set(STAGE_ORDER)
    assert charts.timeline_figure(cases["intrusion"]).layout.yaxis.categoryarray


@pytest.mark.parametrize("name,expected", [("breach", "Likely first compromised host: 192.168.1.20"),
                                           ("intrusion", "Likely first compromised host: 192.168.1.50"),
                                           ("clean", "No suspicious activity")])
def test_sample_buttons_run_end_to_end(name, expected, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("TRACEHOUND_HOME", str(tmp_path))
    app = os.path.join(os.path.dirname(charts.__file__), "dashboard.py")
    at = AppTest.from_file(app, default_timeout=120).run()
    assert not at.exception and any("Find the breach" in m.value for m in at.markdown)  # landing page first
    next(b for b in at.button if b.key == f"main_{name}").click().run()
    assert not at.exception
    text = " ".join(m.value for m in [*at.markdown, *at.error, *at.success])
    assert expected in text and len(at.tabs) == 8


def test_traffic_chart_dims_the_future(cases):
    inv = cases["breach"]
    full = charts.traffic_over_time(inv)
    early = charts.traffic_over_time(inv, until=inv.findings[1].first_seen)
    assert not full.layout.shapes or all(sh.type == "line" for sh in full.layout.shapes)
    assert any(sh.type == "rect" for sh in early.layout.shapes)  # dimmed future
    assert len(early.layout.shapes) - 1 < len(full.layout.shapes)  # later findings are hidden


def _app(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("TRACEHOUND_HOME", str(tmp_path))
    app = os.path.join(os.path.dirname(charts.__file__), "dashboard.py")
    at = AppTest.from_file(app, default_timeout=120).run()
    next(b for b in at.button if b.key == "main_breach").click().run()
    return at


def test_replay_scrubbing_shows_only_what_had_happened(tmp_path, monkeypatch, cases):
    at = _app(tmp_path, monkeypatch)
    inv = cases["breach"]
    at.select_slider(key="replay_step").set_value(2).run()
    assert not at.exception
    score = ui.risk_score(inv.findings[:2])[0]
    html = " ".join(m.value for m in at.markdown)
    assert f'<span class="num" style="color:' in html and f">{score}</span>" in html
    so_far = [m.value for m in at.markdown if m.value.startswith(("**\u25b6**", "&nbsp;&nbsp;")) and "badge[" in m.value]
    assert len(so_far) == 2 and inv.findings[1].id in so_far[-1]  # only the first two findings revealed, latest marked
    at.select_slider(key="replay_step").set_value(0).run()
    assert not at.exception and any("Nothing suspicious has happened yet" in i.value for i in at.info)


def test_replay_play_pause_and_restart(tmp_path, monkeypatch, cases):
    at = _app(tmp_path, monkeypatch)
    at.button(key="replay_play").click().run()
    assert at.session_state["playing"] is True and not at.exception
    at.button(key="replay_play").click().run()
    assert at.session_state["playing"] is False
    at.select_slider(key="replay_step").set_value(3).run()
    at.button(key="replay_restart").click().run()
    assert at.session_state["replay_step"] == 0 and not at.exception
