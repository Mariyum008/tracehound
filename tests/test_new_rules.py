"""New rules: brute force, DNS tunneling and lateral movement, with false-alarm checks."""
import pytest

from tracehound.detectors import Thresholds, run_all
from tracehound.investigation import Investigation
from tracehound.synthetic import (ATTACKER_IP, SERVER, TUNNEL_DOMAIN, write_breach_scenario,
                                  write_clean_scenario, write_intrusion_scenario)


@pytest.fixture(scope="module")
def intrusion(tmp_path_factory):
    return Investigation.open(write_intrusion_scenario(str(tmp_path_factory.mktemp("cap") / "intrusion.pcap")))


def by_rule(inv, rule):
    return [f for f in inv.findings if f.rule == rule]


def test_brute_force_detected(intrusion):
    f, = by_rule(intrusion, "brute_force")
    assert f.hosts == [ATTACKER_IP, SERVER] and "SSH" in f.title and "T1110" in f.mitre


def test_dns_tunnel_detected(intrusion):
    f, = by_rule(intrusion, "dns_tunneling")
    assert f.hosts == [SERVER] and TUNNEL_DOMAIN in f.title


def test_lateral_movement_names_every_hop(intrusion):
    f, = by_rule(intrusion, "lateral_movement")
    assert f.hosts[0] == SERVER and len(f.hosts) == 5 and f.severity == "critical"
    assert {"SMB", "RDP", "WinRM"} <= set(f.title.split(" used ")[1].split(" on ")[0].split("/"))


def test_server_is_first_compromised(intrusion):
    assert intrusion.patient_zero() == SERVER


def test_new_evidence_frames_exist(intrusion):
    for rule in ("brute_force", "dns_tunneling", "lateral_movement"):
        for ev in intrusion.evidence(by_rule(intrusion, rule)[0].evidence_frames):
            assert ev["summary"] != "frame not found in capture"


def test_new_rules_silent_on_old_scenarios(tmp_path):
    # The SMB sweep (no data exchanged) must stay a port scan, not lateral movement
    for path in (write_breach_scenario(str(tmp_path / "b.pcap")), write_clean_scenario(str(tmp_path / "c.pcap"))):
        rules = {f.rule for f in Investigation.open(path).findings}
        assert not rules & {"brute_force", "dns_tunneling", "lateral_movement"}


def test_thresholds_control_new_rules(intrusion):
    strict = Thresholds(brute_min_attempts=100, tunnel_min_names=100, lateral_min_hosts=10)
    rules = {f.rule for f in run_all(intrusion.store, strict)}
    assert not rules & {"brute_force", "dns_tunneling", "lateral_movement"}
