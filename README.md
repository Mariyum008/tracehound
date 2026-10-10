# Tracehound

**AI-assisted breach investigation for packet captures.** Give it a `.pcap` from a suspected incident and it tells you what happened, how it happened, and proves every claim with packet evidence you can check in Wireshark.

```
$ tracehound report demo_breach.pcap

Likely first compromised host: 192.168.1.20

08:56:40  CRITICAL  [Initial Access]       Suspicious download by 192.168.1.20         [frame 262]
08:57:40  HIGH      [Credential Access]    Credentials sent unencrypted over HTTP      [frame 416]
08:58:20  HIGH      [Command and Control]  12 random-looking domains (DGA)             [frames 417, 421, ...]
08:58:27            192.168.1.20 resolved q7x9k2m4vb8z.top to 203.0.113.50             [frame 442]
08:58:41  HIGH      [Command and Control]  Regular beaconing every 60s to the C2       [frames 443, 453, ...]
09:09:10  HIGH      [Lateral Movement]     Network sweep on port 445 (SMB)             [frames 493, 498, ...]
09:10:00  CRITICAL  [Exfiltration]         6.3 MB uploaded to the C2 server            [frames 747, 1573, ...]
```

Full sample output: [`examples/demo_report.md`](examples/demo_report.md)

## Why this exists

Wireshark shows you everything but tells you nothing. Finding a breach in a capture means knowing what to look for and digging by hand, which is slow even for experienced analysts.

Existing AI + Wireshark integrations (MCP servers such as mcpcap) let an AI query raw protocol data, but they leave the investigation and the trust problem to the model. Commercial products (Darktrace Cyber AI Analyst, Microsoft Security Copilot) do full investigations, but they are closed and enterprise-priced.

Tracehound sits in between, with three design principles:

1. **Detect first, explain second.** Deterministic detection rules find the suspicious activity. The AI only explains what the rules found. It never guesses from raw packets.
2. **Every claim cites evidence.** Findings carry frame numbers. A `verify_claim` tool and a citation checker reject anything the evidence does not support.
3. **Index once, query fast.** The capture is parsed once into DuckDB, so every follow-up question is a SQL query instead of a re-parse.

## How it works

```
 .pcap / .pcapng
      |
  [ parser ]      scapy streams packets -> packets, DNS, HTTP, TLS SNI, cleartext-auth tables
      |
  [ store ]       DuckDB in memory + IP-to-domain map (DNS answers, SNI, HTTP Host)
      |
  [ detectors ]   6 rules -> Findings (severity, kill-chain stage, MITRE ATT&CK, evidence frames)
      |
  [ timeline ]    ordered attack story + likely first compromised host
      |
      +--> tracehound dashboard  Streamlit app: charts, network map, chat with Claude, open frames in Wireshark
      +--> tracehound report     Markdown / JSON report (no AI)
      +--> tracehound explain    Claude writes the narrative, citations are checked
      +--> tracehound-mcp        MCP server: Claude Desktop investigates interactively
```

## Detection rules

| Rule | What it catches | MITRE ATT&CK |
|---|---|---|
| `suspicious_download` | Executables/scripts over HTTP, scripted user-agents (PowerShell, BITS, curl), requests to raw IPs | T1105 Ingress Tool Transfer |
| `cleartext_credentials` | Passwords in HTTP forms, Basic auth, FTP/POP3/IMAP/SMTP/Telnet logins | T1552 Unsecured Credentials |
| `suspicious_domains` | High-entropy, random-looking domain names (with a CDN allowlist) | T1568.002 Domain Generation Algorithms |
| `nxdomain_burst` | Many failed DNS lookups from one host | T1568.002 Domain Generation Algorithms |
| `beaconing` | Outbound connections at machine-regular intervals (median period, outlier tolerant) | T1071 Application Layer Protocol |
| `port_scan` | Vertical scans (many ports, one host) and horizontal sweeps (one port, many hosts) | T1046 Network Service Discovery |
| `data_exfiltration` | Large, lopsided uploads from an internal host to an outside server | T1041 Exfiltration Over C2 Channel |

All thresholds live in `Thresholds` in [`detectors.py`](src/tracehound/detectors.py).

## Install

```bash
git clone https://github.com/AiMk937/tracehound.git
cd tracehound
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Optional, for live capture and "Open in Wireshark": install [Wireshark](https://www.wireshark.org/download.html). On macOS, also run **Install ChmodBPF.pkg** from the Wireshark disk image so tshark can capture without admin rights, then log out and back in.

## Dashboard

```bash
export ANTHROPIC_API_KEY=sk-ant-...     # optional; you can also paste it in the sidebar
tracehound dashboard                     # opens http://localhost:8501
```

| Tab | What you get |
|---|---|
| **Timeline** | Findings plotted by kill-chain stage and time, each with an *Open in Wireshark* button |
| **Findings** | Severity, MITRE technique, evidence packets, and the exact Wireshark display filter |
| **Traffic** | Volume over time with findings marked, top talkers, protocol mix |
| **Network map** | Who talked to whom; compromised paths in red, scan targets collapsed |
| **Ask Claude** | Chat about the capture. Claude calls Tracehound's tools, cites frames, and invented frames are flagged |
| **Report** | Download the evidence report or a Claude-written incident report as Word (.docx) or Markdown |

Sources: open a file saved from Wireshark, **monitor live traffic** (tshark captures in the background and the dashboard re-analyzes every 5-60 seconds, keeping your chat with Claude), run a fixed-length capture, or load the built-in demo breach. Captures are stored in `~/.tracehound/captures`.

**Wireshark round trip:** every *Open in Wireshark* button launches Wireshark on the same file, jumps to the first evidence frame and applies a `frame.number in {...}` filter, so you and Claude are looking at the same packets.

**API cost:** the chat uses the Anthropic API (Sonnet 5.5 by default; Haiku 5.5 is cheaper). The long capture summary in the system prompt is cached to keep repeat questions cheaper, and only questions and answers are kept between turns, not raw tool output.

## Command line

```bash
tracehound demo                                  # generate a synthetic breach capture
tracehound report demo_breach.pcap               # Markdown report
tracehound report demo_breach.pcap --json        # machine-readable
tracehound report capture.pcapng -o report.md    # save to file

export ANTHROPIC_API_KEY=...                     # Windows PowerShell: $env:ANTHROPIC_API_KEY="..."
tracehound explain demo_breach.pcap              # AI-written incident narrative + citation check
```

### Use it from Claude Desktop (MCP)

Add this to Claude Desktop's config file (Settings > Developer > Edit Config), using the full path to the `tracehound-mcp` executable in your virtual environment:

```json
{
  "mcpServers": {
    "tracehound": {
      "command": "/full/path/to/tracehound/.venv/bin/tracehound-mcp"
    }
  }
}
```

On Windows the path looks like `C:\\Users\\you\\tracehound\\.venv\\Scripts\\tracehound-mcp.exe`. Restart Claude Desktop, then ask: *"Investigate the capture at /path/to/demo_breach.pcap"* or pick the `investigate_breach` prompt.

| MCP tool | Purpose |
|---|---|
| `load_capture` | Parse, index and run detections on a capture |
| `capture_overview` | Time window, hosts, top talkers, protocol mix |
| `find_threats` | Detection findings with evidence frames |
| `build_timeline` | Ordered attack story and first compromised host |
| `investigate_host` | Everything one host did |
| `search_capture` | Find frames by IP, domain, URL, SNI or user-agent |
| `get_evidence` | Readable summaries of specific frames |
| `verify_claim` | Confirm cited frames contain what a claim says |

## Zeek logs

Tracehound also investigates [Zeek](https://zeek.org) logs, the network-monitoring format many security teams already collect. Point any command at a folder of logs instead of a pcap:

```bash
tracehound report /path/to/zeek/logs        # folder with conn.log, dns.log, http.log, ssl.log (ftp.log optional)
tracehound demo --zeek                      # writes the demo breach as Zeek logs to ./demo_zeek
```

In the dashboard choose **Zeek logs** and upload the files or type the folder path. TSV and JSON logs both work, gzip included.

Differences from pcap input:
- Zeek has no packet frames, so evidence cites Tracehound record IDs with the **Zeek log and uid** they came from (for example `[http.log uid=CHhAvVGS1DHFjwGM9]`), and the *Open in Wireshark* buttons are replaced by the uids.
- Zeek does not record payloads, so passwords in HTTP POST bodies are not visible. HTTP Basic auth and FTP logins still are.
- Byte counts come from conn.log totals per connection rather than individual packets.

To compare both views of the same traffic: `zeek -r capture.pcap` (install with `brew install zeek`) produces the logs, then run `tracehound report` on the pcap and on the log folder.

## Evaluation

```bash
tracehound eval evaluation --demo     # try the harness on two synthetic cases
tracehound eval evaluation            # score every capture that has an answers.json
```

Scores Tracehound against breach captures with known answers: first infected host, infected-host recall and precision, indicator-of-compromise recall, and false alarms on clean traffic. It also lists exactly what was missed. See [EVALUATION.md](EVALUATION.md) for adding real cases safely.

## Testing

```bash
pytest -q
```

43 tests. The suite builds a synthetic breach (dropper download, cleartext password, DGA, C2 beaconing, SMB sweep, exfiltration) hidden among normal browsing, plus a clean baseline. It checks that every stage is detected, that clean traffic produces **zero** findings, that the timeline is in attack order, that every evidence frame exists, and that `verify_claim` and the citation checker reject invented evidence. Dashboard tests cover the Claude tool-use loop (with a scripted fake client, so no API key is needed), the Wireshark bridge and live monitoring (with fake tshark/wireshark executables, including a streaming capture and a macOS permission-denied case), the charts, Word export, and a headless render of the whole app. Zeek tests check that the Zeek pipeline finds the same attack stages as the pcap pipeline, in both TSV and JSON, and that logs in the exact header layout of Zeek's own test baselines (masked timestamps, extra columns, unset and empty fields, gzip) parse correctly.

## Limitations

- **Encrypted traffic:** for HTTPS, Tracehound sees who talked to whom, when and how much (plus the TLS server name), not the content.
- **Network view only:** it cannot see processes, files or registry changes on hosts. Real investigations combine this with endpoint logs.
- **Memory:** the capture is loaded into memory. Use `--max-packets` for very large files.
- **Synthetic validation so far:** the evaluation harness is built; scores on real-world captures are the next milestone.

## Roadmap

- [x] Evaluation harness with accuracy scoring (`tracehound eval`, see [EVALUATION.md](EVALUATION.md))
- [ ] Publish scores on 10+ real breach exercises from Malware-Traffic-Analysis.net
- [x] Streamlit dashboard with Claude chat, charts, network map and Wireshark integration
- [x] Live monitoring with auto-refresh
- [ ] More protocols: SMB, Kerberos, TLS certificates, JA3/JA4 fingerprints
- [x] Zeek log ingestion (conn, dns, http, ssl, ftp; TSV or JSON; gzip)
- [ ] Local model support (Ollama) for captures that must not leave the machine

## Safety

Only analyze traffic you are authorized to capture. Do not commit real captures to Git: `.gitignore` excludes `*.pcap` and `*.pcapng` because they contain IPs, DNS history and sometimes credentials.

## License

MIT
