"""Zeek log ingestion: real-format parsing edge cases and detection parity with the pcap pipeline."""
import gzip
import json
import os

import pytest

from tracehound import evaluate
from tracehound.investigation import Investigation
from tracehound.synthetic import C2_DOMAIN, C2_IP, VICTIM, write_breach_scenario, write_zeek_breach
from tracehound.zeek import is_zeek_source, parse_zeek, read_log

# Header layout copied from Zeek's own test baselines: masked timestamps, extra columns, unset and empty values
REAL_STYLE_HTTP = (
    "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\thttp\n"
    "#open\tXXXX-XX-XX-XX-XX-XX\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\ttrans_depth\tmethod\thost\turi\treferrer\tversion\t"
    "user_agent\torigin\trequest_body_len\tresponse_body_len\tstatus_code\tstatus_msg\tinfo_code\tinfo_msg\ttags\t"
    "username\tpassword\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tcount\tstring\tstring\tstring\tstring\tstring\tstring\tstring\t"
    "count\tcount\tcount\tstring\tcount\tstring\tset[enum]\tstring\tstring\n"
    "XXXXXXXXXX.XXXXXX\tCHhAvVGS1DHFjwGM9\t172.24.133.205\t43090\t172.24.133.205\t8000\t1\tGET\t172.24.133.205:8000\t/\t-\t"
    "1.0\tpython-requests/2.31.0\t-\t0\t643\t200\tOK\t-\t-\t(empty)\ttest\t1:34\n"
    "#close\tXXXX-XX-XX-XX-XX-XX\n")


@pytest.fixture(scope="module", params=["tsv", "json"])
def zeek_breach(request, tmp_path_factory):
    return Investigation.open(write_zeek_breach(str(tmp_path_factory.mktemp(request.param)), fmt=request.param))


def test_zeek_detects_every_stage_like_pcap(zeek_breach, tmp_path):
    pcap = Investigation.open(write_breach_scenario(str(tmp_path / "b.pcap")))
    assert {f.rule for f in zeek_breach.findings} == {f.rule for f in pcap.findings}
    assert zeek_breach.patient_zero() == VICTIM
    exfil = next(f for f in zeek_breach.findings if f.rule == "data_exfiltration")
    assert C2_IP in exfil.hosts and C2_DOMAIN in exfil.title


def test_zeek_evidence_names_log_and_uid(zeek_breach):
    assert zeek_breach.overview()["source"] == "zeek"
    for f in zeek_breach.findings:
        for ev in zeek_breach.evidence(f.evidence_frames):
            assert ".log uid=C" in ev["summary"]


def test_real_style_header_masked_time_and_basic_auth(tmp_path):
    log = tmp_path / "http.log"
    log.write_text(REAL_STYLE_HTTP)
    row = read_log(log)[0]
    assert row["tags"] == [] and row["referrer"] is None and row["username"] == "test"
    cap = parse_zeek(str(log))
    assert len(cap.http) == 1 and cap.auth[0][5] == "HTTP"  # basic auth flagged as cleartext credentials


def test_gzip_and_folder_detection(tmp_path):
    with gzip.open(tmp_path / "http.log.gz", "wt") as fh:
        fh.write(REAL_STYLE_HTTP)
    assert is_zeek_source(str(tmp_path)) and len(parse_zeek(str(tmp_path)).http) == 1
    assert not is_zeek_source(str(tmp_path / "missing"))


def test_zeek_case_in_evaluation(tmp_path):
    case = tmp_path / "zeek-case"
    write_zeek_breach(str(case))
    (case / "answers.json").write_text(json.dumps({"name": "zeek", "infected_hosts": [VICTIM],
                                                   "iocs": {"ips": [C2_IP], "domains": [C2_DOMAIN]}}))
    results, summary = evaluate.run(str(tmp_path))
    assert summary["cases"] == 1 and summary["patient_zero_accuracy"] == 1.0 and summary["ioc_recall"] == 1.0


def test_dashboard_with_zeek_has_no_wireshark_buttons(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    import tracehound.charts as charts
    monkeypatch.setenv("TRACEHOUND_HOME", str(tmp_path / "home"))
    app = os.path.join(os.path.dirname(charts.__file__), "dashboard.py")
    at = AppTest.from_file(app, default_timeout=120)
    at.session_state["pcap"] = write_zeek_breach(str(tmp_path / "logs"))
    at.run()
    assert not at.exception
    assert at.metric[0].label == "Zeek records"
    assert not any("in Wireshark" in b.label for b in at.button)
    assert any("Zeek uid" in c.value for c in at.caption)
