"""Command line: `tracehound report`, `tracehound explain`, `tracehound serve`, `tracehound demo`."""
from __future__ import annotations

import argparse
import json
import sys

from .investigation import Investigation


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tracehound", description="AI-assisted breach investigation for packet captures")
    sub = ap.add_subparsers(dest="cmd", required=True)

    rp = sub.add_parser("report", help="detect threats and print a Markdown breach report (no AI needed)")
    rp.add_argument("pcap", help="a .pcap/.pcapng file, or a Zeek log folder or log file")
    rp.add_argument("-o", "--output", help="write the report to this file")
    rp.add_argument("--json", action="store_true", help="print findings and timeline as JSON")
    rp.add_argument("--max-packets", type=int)

    ex = sub.add_parser("explain", help="AI-written breach story with citation checking (needs ANTHROPIC_API_KEY)")
    ex.add_argument("pcap")
    ex.add_argument("-o", "--output")
    ex.add_argument("--model", default=None)
    ex.add_argument("--max-packets", type=int)

    sub.add_parser("serve", help="run the MCP server over stdio (for Claude Desktop and other MCP clients)")

    db = sub.add_parser("dashboard", help="open the interactive dashboard in your browser")
    db.add_argument("--port", type=int, default=8501)

    dm = sub.add_parser("demo", help="generate a synthetic breach capture to try the tool on")
    dm.add_argument("-o", "--output", default="demo_breach.pcap")
    dm.add_argument("--zeek", action="store_true", help="write the demo as Zeek logs (a folder) instead of a pcap")

    ev = sub.add_parser("eval", help="score Tracehound against captures with known answers")
    ev.add_argument("folder", nargs="?", default="evaluation", help="folder of cases (capture + answers.json)")
    ev.add_argument("--demo", action="store_true", help="create two synthetic cases first, to try the harness")
    ev.add_argument("--new-case", metavar="CAPTURE", help="create a blank answer key next to this capture")
    ev.add_argument("-o", "--output", help="where to write results (default: the cases folder)")

    args = ap.parse_args(argv)

    if args.cmd == "eval":
        import json as _json  # local alias so the module-level json import is not shadowed
        from pathlib import Path
        from . import evaluate
        if args.new_case:
            # Blank answer key next to the capture, for the user to fill in from the exercise's answers
            key = Path(args.new_case).with_name(Path(args.new_case).name + ".answers.json")
            key.write_text(_json.dumps(evaluate.TEMPLATE, indent=2))
            print(f"Created {key}\nFill it in from the exercise's answers page, then run: tracehound eval {key.parent}")
            return 0
        if args.demo:
            evaluate.write_demo_cases(args.folder)
        cases = evaluate.find_cases(args.folder)
        if not cases:
            print(f"No cases found in '{args.folder}'. Each capture needs an answer key: "
                  f"run 'tracehound eval --new-case path/to/capture.pcap' to create one.")
            return 1
        print(f"Scoring {len(cases)} case(s)...")
        results, summary = evaluate.run(args.folder, args.output)
        print(evaluate.markdown(results, summary))
        print(f"Saved results.md, results.json and results.csv to {args.output or args.folder}")
        return 0

    if args.cmd == "serve":
        from .server import main as serve
        serve()
        return 0

    if args.cmd == "dashboard":
        # Launch Streamlit on the bundled app file
        import subprocess
        from pathlib import Path
        app = Path(__file__).with_name("dashboard.py")
        cmd = [sys.executable, "-m", "streamlit", "run", str(app), "--server.port", str(args.port),
               "--browser.gatherUsageStats", "false", "--server.fileWatcherType", "none"]  # no watchdog nag
        print("Starting Tracehound dashboard... press Ctrl+C here to stop it.")
        try:
            return subprocess.call(cmd)
        except KeyboardInterrupt:  # Ctrl+C is the normal way to stop, so exit quietly
            print("\nDashboard stopped.")
            return 0

    if args.cmd == "demo":
        from .synthetic import write_breach_scenario, write_zeek_breach
        if args.zeek:
            path = write_zeek_breach("demo_zeek" if args.output == "demo_breach.pcap" else args.output)
        else:
            path = write_breach_scenario(args.output)
        print(f"Wrote synthetic breach capture to {path}\nTry: tracehound report {path}")
        return 0

    inv = Investigation.open(args.pcap, args.max_packets)

    if args.cmd == "report":
        if args.json:
            out = json.dumps({"overview": inv.overview(), "likely_first_compromised_host": inv.patient_zero(),
                              "findings": inv.findings_list(), "timeline": inv.timeline()}, indent=2, default=str)
        else:
            from .report import markdown_report
            out = markdown_report(inv)
    else:
        from .narrator import narrate, DEFAULT_MODEL
        res = narrate(inv, model=args.model or DEFAULT_MODEL)
        c = res["citations"]
        footer = (f"\n\n---\n**Citation check:** {len(c['cited_frames'])} frames cited, "
                  f"{len(c['nonexistent'])} not in capture, {len(c['outside_evidence'])} outside detected evidence. "
                  + ("All citations valid." if c["ok"] else "Review flagged citations before trusting this report."))
        out = res["narrative"] + footer

    if getattr(args, "output", None):
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Saved to {args.output}")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
