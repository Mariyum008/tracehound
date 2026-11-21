"""MCP server: lets Claude (or any MCP client) investigate captures with evidence-backed tools."""
from __future__ import annotations

import os

try:  # MCP SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # MCP SDK 1.x
    from mcp.server.fastmcp import FastMCP as _Server

from .investigation import Investigation

INSTRUCTIONS = """Tracehound investigates network packet captures for signs of a breach.
Always start with load_capture. Prefer find_threats and build_timeline over raw searching.
Every factual claim you make must cite frame numbers, and run verify_claim on key claims before reporting them.
Use the investigate_breach prompt for a full SOC-style investigation."""

mcp = _Server("tracehound", instructions=INSTRUCTIONS)
_open: dict[str, Investigation] = {}   # loaded once per path, then reused
_current: list[str] = []


def _inv(capture: str | None) -> Investigation:
    # Use the named capture, or the most recently loaded one
    key = os.path.abspath(os.path.expanduser(capture)) if capture else (_current[-1] if _current else None)
    if not key or key not in _open:
        raise ValueError("No capture loaded. Call load_capture with the path to a .pcap/.pcapng file first.")
    return _open[key]


@mcp.tool()
def load_capture(path: str, max_packets: int | None = None) -> dict:
    """Parse a .pcap/.pcapng file or a Zeek log folder, index it, and run all detection rules. Returns an overview."""
    key = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(key):
        raise ValueError(f"File not found: {key}")
    if key not in _open:
        _open[key] = Investigation.open(key, max_packets)
    _current.append(key)
    return _open[key].overview()


@mcp.tool()
def capture_overview(capture: str | None = None) -> dict:
    """Packet counts, time window, internal hosts, top talkers, protocol mix and finding counts."""
    return _inv(capture).overview()


@mcp.tool()
def find_threats(min_severity: str = "low", capture: str | None = None) -> list[dict]:
    """Detection-rule findings (downloads, cleartext credentials, DGA domains, beaconing, scans, exfiltration),
    each with severity, kill-chain stage, MITRE ATT&CK technique and evidence frame numbers."""
    return _inv(capture).findings_list(min_severity)


@mcp.tool()
def build_timeline(capture: str | None = None) -> dict:
    """Chronological attack story built from the findings, plus the likely first compromised host."""
    inv = _inv(capture)
    return {"likely_first_compromised_host": inv.patient_zero(),
            "timeline": [{k: v for k, v in e.items() if k != "time"} for e in inv.timeline()]}


@mcp.tool()
def investigate_host(ip: str, capture: str | None = None) -> dict:
    """Everything one host did: destinations, DNS lookups, HTTP requests, TLS servers, data volumes and related findings."""
    return _inv(capture).host_profile(ip)


@mcp.tool()
def search_capture(text: str, capture: str | None = None) -> list[dict]:
    """Find frames whose IP, domain, URL, TLS server name or user-agent contains the text."""
    return _inv(capture).search(text)


@mcp.tool()
def get_evidence(frames: list[int], capture: str | None = None) -> list[dict]:
    """Readable summaries of specific frames (max 200). Use to show proof for a claim."""
    return _inv(capture).evidence(frames)


@mcp.tool()
def verify_claim(frames: list[int], must_mention: list[str], capture: str | None = None) -> dict:
    """Check that the cited frames really contain every host, domain or string the claim depends on.
    Example: verify_claim([412, 413], ["10.0.0.5", "evil.top"])."""
    return _inv(capture).verify_claim(frames, must_mention)


@mcp.prompt()
def investigate_breach(path: str) -> str:
    """Guided SOC-analyst playbook for investigating a capture end to end."""
    return f"""Investigate the packet capture at {path} as a SOC analyst would.

1. load_capture("{path}") and summarize the capture window and hosts.
2. find_threats and build_timeline. Identify the likely first compromised host.
3. For that host, investigate_host and follow the trail: how it was first compromised, what it contacted,
   whether it moved to other hosts, whether data left the network.
4. For each key claim, call verify_claim with the frames and the hosts/domains the claim names. Drop or
   correct anything that fails verification.
5. Write the report: Summary, Step-by-step timeline (with MITRE techniques), Initial access,
   Affected hosts and indicators of compromise, Recommended actions, Limits of the analysis.
Cite every fact as [frame N]. If network data cannot show something (for example contents of encrypted
traffic or the malware family), say so instead of guessing."""


def main():
    mcp.run()


if __name__ == "__main__":
    main()
