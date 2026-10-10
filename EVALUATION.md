# Evaluating Tracehound on real breach traffic

Synthetic tests prove the code works. This guide measures whether Tracehound finds **real** infections, by scoring it against public training exercises that come with published answers.

## 1. Try the harness first (no downloads)

```bash
tracehound eval evaluation --demo
```

This creates two synthetic cases in `evaluation/` and scores them. You should see 100% across the board and `0 of 1` clean captures with false alarms. That confirms the harness works. It says nothing about real-world accuracy yet.

## 2. Safety rules for real malware traffic

The exercises below are captures of **real infections**.

- Work in a virtual machine if you can (UTM is free on Apple Silicon Macs).
- Extract **only** the `.pcap` / `.pcapng` file from each zip. If a zip contains anything else (executables, documents, scripts), delete it without opening it.
- Never use Wireshark's *File > Export Objects* to save files out of these captures.
- Never commit the captures to Git. `.gitignore` already excludes `*.pcap` and `*.pcapng`.

## 3. Add a case

1. Go to **malware-traffic-analysis.net** and open the **Traffic analysis exercises** section.
2. Pick an exercise and download its zip. The zip password is given on the site's About page.
3. Make a folder per exercise and put the capture inside:
   ```
   evaluation/
     2026-01-15-example/
       capture.pcap
   ```
4. Create a blank answer key:
   ```bash
   tracehound eval --new-case evaluation/2026-01-15-example/capture.pcap
   ```
5. **Do not look at the answers yet if you want to practice first.** Investigate the capture yourself in the dashboard and Wireshark, then open the exercise's answers page.
6. Fill in `capture.pcap.answers.json` from the answers page:
   ```json
   {
     "name": "2026-01-15 example infection",
     "source_url": "https://www.malware-traffic-analysis.net/...",
     "infected_hosts": ["10.1.17.215"],
     "iocs": {
       "ips": ["193.42.33.7"],
       "domains": ["badsite.example"]
     },
     "notes": "Malware family and anything else worth remembering"
   }
   ```
   Only copy what the answers actually state. Leave a list empty rather than guessing.

Zeek cases work too: put the Zeek logs in the case folder (no pcap) with an `answers.json` beside them.

## 4. Score everything

```bash
tracehound eval evaluation
```

This writes `evaluation/results.md`, `results.json` and `results.csv`.

| Metric | What it means |
|---|---|
| First infected host correct | Tracehound's "likely first compromised host" matches the answer key |
| Infected hosts found (recall) | Share of truly infected hosts named in a high/critical finding |
| Precision | Share of accused hosts that were really infected (low = false alarms) |
| IOC recall | Share of known bad IPs/domains that appear in the findings or their evidence |
| Clean captures with false alarms | Captures with no infection where Tracehound still accused a host |

## 5. Turn misses into improvements

The **What was missed** section lists every host and indicator Tracehound did not find. For each one:

1. Search for it in the dashboard (Findings tab) or Wireshark: `ip.addr == X` or `dns.qry.name contains "X"`.
2. Ask: what did the traffic look like, and which rule should have caught it?
3. Either tune a threshold in `Thresholds` (`src/tracehound/detectors.py`) or write a new rule, then re-run `tracehound eval evaluation` and check the score went up **without** new false alarms on clean captures.

Commit `answers.json` files and `results.md` (they contain no packet data), so the scores are visible on GitHub.

## Aim for

- **10 or more** real exercises across different malware families
- **2 or more** clean captures of your own normal traffic (`infected_hosts: []`) to measure false alarms

Report the honest numbers, including the misses. In an interview, "it finds the infected host in 7 of 10 real cases, and here is why it misses the other 3" is far more convincing than a claim of perfection.
