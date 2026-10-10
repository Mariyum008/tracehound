"""The evaluation harness must reward correct answers and clearly report misses."""
import json

from tracehound import evaluate
from tracehound.cli import main as cli_main
from tracehound.synthetic import C2_DOMAIN, VICTIM, write_breach_scenario


def make_case(tmp_path, answers):
    cap = write_breach_scenario(str(tmp_path / "case.pcap"))
    (tmp_path / "case.pcap.answers.json").write_text(json.dumps(answers))
    return evaluate.find_cases(str(tmp_path))


def test_demo_cases_score_perfectly(tmp_path):
    evaluate.write_demo_cases(str(tmp_path))
    results, summary = evaluate.run(str(tmp_path))
    assert summary["cases"] == 2 and summary["patient_zero_accuracy"] == 1.0
    assert summary["ioc_recall"] == 1.0 and summary["infected_host_precision"] == 1.0
    assert summary["clean_cases"] == 1 and summary["clean_cases_with_alerts"] == 0
    assert (tmp_path / "results.md").exists() and (tmp_path / "results.csv").exists()


def test_misses_are_reported(tmp_path):
    # Answer key names a host and indicators that the capture never shows
    (cap, key), = make_case(tmp_path, {"name": "wrong", "infected_hosts": ["10.9.9.9"],
                                       "iocs": {"ips": ["198.18.0.1"], "domains": [C2_DOMAIN, "never-seen.example"]}})
    r = evaluate.score_case(cap, key)
    assert not r.patient_zero_correct and r.hosts_missed == ["10.9.9.9"]
    assert VICTIM in r.extra_hosts_flagged
    assert r.iocs_found == [C2_DOMAIN] and set(r.iocs_missed) == {"198.18.0.1", "never-seen.example"}
    md = evaluate.markdown([r], evaluate.summarize([r]))
    assert "What was missed" in md and "never-seen.example" in md


def test_broken_capture_does_not_stop_run(tmp_path):
    (tmp_path / "bad.pcap").write_bytes(b"not a capture at all")
    (tmp_path / "bad.pcap.answers.json").write_text(json.dumps({"name": "bad", "infected_hosts": [VICTIM]}))
    evaluate.write_demo_cases(str(tmp_path / "demo"))
    results, summary = evaluate.run(str(tmp_path))
    assert summary["cases"] == 3


def test_cli_new_case_and_eval(tmp_path, capsys):
    cap = write_breach_scenario(str(tmp_path / "x.pcap"))
    assert cli_main(["eval", "--new-case", cap]) == 0
    key = tmp_path / "x.pcap.answers.json"
    data = json.loads(key.read_text())
    data.update(infected_hosts=[VICTIM], iocs={"ips": [], "domains": [C2_DOMAIN]})
    key.write_text(json.dumps(data))
    assert cli_main(["eval", str(tmp_path)]) == 0
    assert "First infected host correct | 100%" in capsys.readouterr().out
