"""End-to-end tests on synthetic captures with known ground truth."""
import json

import pytest

from tracehound.cli import main as cli_main
from tracehound.investigation import Investigation, check_citations
from tracehound.parser import _tls_sni
from tracehound.store import is_internal
from tracehound.synthetic import (C2_DOMAIN, C2_IP, DROPPER_IP, VICTIM, client_hello,
                                  write_breach_scenario, write_clean_scenario)


@pytest.fixture(scope="module")
def breach(tmp_path_factory):
    return Investigation.open(write_breach_scenario(str(tmp_path_factory.mktemp("cap") / "breach.pcap")))


@pytest.fixture(scope="module")
def clean(tmp_path_factory):
    return Investigation.open(write_clean_scenario(str(tmp_path_factory.mktemp("cap") / "clean.pcap")))


def rules(inv):
    return {f.rule for f in inv.findings}


# --- every attack stage in the scenario is detected -----------------------------

def test_detects_every_stage(breach):
    assert rules(breach) == {"suspicious_download", "cleartext_credentials", "suspicious_domains",
                             "nxdomain_burst", "beaconing", "port_scan", "data_exfiltration"}


def test_clean_traffic_has_no_findings(clean):
    assert clean.findings == []


def test_patient_zero_is_victim(breach):
    assert breach.patient_zero() == VICTIM


def test_beacon_and_exfil_point_at_c2(breach):
    for rule in ("beaconing", "data_exfiltration"):
        f = next(f for f in breach.findings if f.rule == rule)
        assert C2_IP in f.hosts and C2_DOMAIN in f.title


def test_download_is_critical_with_all_reasons(breach):
    f = next(f for f in breach.findings if f.rule == "suspicious_download")
    assert f.severity == "critical" and DROPPER_IP in f.description and "invoice_8841.exe" in f.description


def test_timeline_is_chronological_and_in_attack_order(breach):
    tl = breach.timeline()
    assert [e["time"] for e in tl] == sorted(e["time"] for e in tl)
    order = [e["finding"] for e in tl if e["kind"] == "finding"]
    stage = {f.id: f.rule for f in breach.findings}
    seq = [stage[i] for i in order]
    assert seq.index("suspicious_download") < seq.index("beaconing") < seq.index("data_exfiltration")
    assert any(e["kind"] == "context" and C2_DOMAIN in e["text"] for e in tl)


# --- evidence is real and verifiable ----------------------------------------------

def test_every_evidence_frame_exists(breach):
    for f in breach.findings:
        assert f.evidence_frames
        for ev in breach.evidence(f.evidence_frames):
            assert ev["summary"] != "frame not found in capture"


def test_verify_claim_accepts_true_and_rejects_false(breach):
    lookup = next(e for e in breach.timeline() if e["kind"] == "context")
    assert breach.verify_claim(lookup["frames"], [C2_DOMAIN, C2_IP])["verified"]
    assert not breach.verify_claim(lookup["frames"], ["evil.example"])["verified"]
    assert not breach.verify_claim([999999], [C2_IP])["verified"]


def test_citation_checker_flags_invented_frames(breach):
    real = breach.findings[0].evidence_frames[0]
    assert check_citations(f"Download seen [frame {real}].", breach)["ok"]
    bad = check_citations(f"Download seen [frame {real}] and data stolen [frames 999999].", breach)
    assert not bad["ok"] and bad["nonexistent"] == [999999]


def test_search_and_host_profile(breach):
    assert any(h["kind"] == "tls" for h in breach.search(C2_DOMAIN))
    prof = breach.host_profile(VICTIM)
    assert prof["internal"] and len(prof["findings"]) == len(breach.findings)


# --- building blocks --------------------------------------------------------------

def test_sni_parser():
    assert _tls_sni(client_hello("example.com")) == "example.com"
    assert _tls_sni(b"not tls at all") is None


@pytest.mark.parametrize("ip,expected", [("10.1.2.3", True), ("192.168.0.9", True), ("172.20.0.1", True),
                                         ("8.8.8.8", False), ("203.0.113.50", False), ("fe80::1", True)])
def test_internal_ranges(ip, expected):
    assert is_internal(ip) is expected


def test_cli_json_report(tmp_path, capsys):
    path = write_breach_scenario(str(tmp_path / "b.pcap"))
    cli_main(["report", path, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["likely_first_compromised_host"] == VICTIM and len(data["findings"]) == 7


def test_narrator_with_fake_client(breach, monkeypatch):
    # No API call: a fake client returns text, and we check the citation check runs on it
    import types, sys
    frame = breach.findings[0].evidence_frames[0]

    class FakeMessages:
        def create(self, **kw):
            assert "Investigation data" in kw["messages"][0]["content"]
            return types.SimpleNamespace(content=[types.SimpleNamespace(type="text", text=f"Dropper fetched [frame {frame}].")])

    fake = types.SimpleNamespace(Anthropic=lambda: types.SimpleNamespace(messages=FakeMessages()))
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    from tracehound.narrator import narrate
    res = narrate(breach)
    assert res["citations"]["ok"] and res["citations"]["cited_frames"] == [frame]
