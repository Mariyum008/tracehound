"""Chat agent: Claude answers questions about a capture by calling Tracehound's investigation tools."""
from __future__ import annotations

import json
import os

from .investigation import Investigation, check_citations

DEFAULT_MODEL = os.environ.get("TRACEHOUND_MODEL", "claude-sonnet-5-5")
MODELS = {"Sonnet 5.5": "claude-sonnet-5-5", "Haiku 5.5": "claude-haiku-5-5", "Opus 5.5": "claude-opus-5-5"}
MAX_TOOL_ROUNDS = 8
MAX_RESULT_CHARS = 15_000

# Tool schemas Claude sees; each maps to an Investigation method in run_tool
TOOLS = [
    {"name": "find_threats", "description": "Detection-rule findings with severity, kill-chain stage, MITRE technique and evidence frames.",
     "input_schema": {"type": "object", "properties": {"min_severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]}}}},
    {"name": "build_timeline", "description": "Chronological attack story and the likely first compromised host.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "investigate_host", "description": "Everything one IP did: destinations, DNS, HTTP, TLS servers, bytes, related findings.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}},
    {"name": "search_capture", "description": "Find frames whose IP, domain, URL, TLS server name or user-agent contains the text.",
     "input_schema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "get_evidence", "description": "Readable summaries of specific frame numbers (max 200).",
     "input_schema": {"type": "object", "properties": {"frames": {"type": "array", "items": {"type": "integer"}}}, "required": ["frames"]}},
    {"name": "verify_claim", "description": "Check the cited frames really contain every host/domain/string a claim depends on.",
     "input_schema": {"type": "object", "properties": {"frames": {"type": "array", "items": {"type": "integer"}},
                                                       "must_mention": {"type": "array", "items": {"type": "string"}}},
                      "required": ["frames", "must_mention"]}},
]

SYSTEM = """You are a senior SOC analyst investigating a network packet capture together with the user, who is
looking at the same capture in a dashboard and in Wireshark.
- Ground every factual statement in tool results. Cite frames as [frame N] or [frames N, M] so the user can open them in Wireshark.
- Use verify_claim before stating anything important about a specific host, domain or file.
- If network data cannot show something (encrypted content, which process ran, malware family), say so plainly.
- Be concise. Explain security terms briefly the first time you use them; the user is learning.
- Suggest a useful Wireshark display filter when it helps the user look for themselves.
- If the source is "zeek", there are no packets: "frame" numbers are Tracehound record IDs mapped to Zeek uids
  (shown in evidence), so point the user to the Zeek uid instead of Wireshark, and remember Zeek does not
  record payloads (for example HTTP POST bodies).

Capture summary (already computed, no tool call needed for these basics):
"""


def run_tool(inv: Investigation, name: str, args: dict):
    # Dispatch a tool call to the investigation and return a JSON-safe result
    if name == "find_threats":
        return inv.findings_list(args.get("min_severity", "low"))
    if name == "build_timeline":
        return {"likely_first_compromised_host": inv.patient_zero(),
                "timeline": [{k: v for k, v in e.items() if k != "time"} for e in inv.timeline()]}
    if name == "investigate_host":
        return inv.host_profile(args["ip"])
    if name == "search_capture":
        return inv.search(args["text"])
    if name == "get_evidence":
        return inv.evidence(args["frames"])
    if name == "verify_claim":
        return inv.verify_claim(args["frames"], args["must_mention"])
    return {"error": f"unknown tool {name}"}


def _block_to_dict(block) -> dict:
    # Normalize SDK content blocks into plain dicts we can send back next turn
    btype = getattr(block, "type", None) or block.get("type")
    get = (lambda k: getattr(block, k)) if not isinstance(block, dict) else block.get
    if btype == "text":
        return {"type": "text", "text": get("text")}
    if btype == "tool_use":
        return {"type": "tool_use", "id": get("id"), "name": get("name"), "input": get("input")}
    return {"type": btype}


class InvestigationAgent:
    """Keeps the conversation; each question may trigger several tool calls before the final answer."""

    def __init__(self, inv: Investigation, model: str = DEFAULT_MODEL, client=None, api_key: str | None = None):
        self.inv, self.model = inv, model
        if client is None:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self.client = client
        self.history: list[dict] = []  # only user questions and final answers, to keep cost down
        ov = inv.overview()
        brief = {"overview": {k: ov[k] for k in ("source", "packets", "start", "end", "duration_seconds", "internal_hosts",
                                                 "protocols", "findings_by_severity")},
                 "likely_first_compromised_host": inv.patient_zero(),
                 "findings": [{"id": f.id, "severity": f.severity, "stage": f.stage, "title": f.title,
                               "evidence_frames": f.evidence_frames} for f in inv.findings]}
        # Cache the long system prompt so repeat questions are cheaper
        self.system = [{"type": "text", "text": SYSTEM + json.dumps(brief, default=str),
                        "cache_control": {"type": "ephemeral"}}]

    def ask(self, question: str, on_tool=None) -> dict:
        """Answer one question. on_tool(name, args) is called for each tool use so the UI can show progress."""
        messages = self.history + [{"role": "user", "content": question}]
        calls, text = [], ""
        for _ in range(MAX_TOOL_ROUNDS):
            resp = self.client.messages.create(model=self.model, max_tokens=4096, system=self.system,
                                               tools=TOOLS, messages=messages)
            blocks = [_block_to_dict(b) for b in resp.content]
            messages.append({"role": "assistant", "content": blocks})
            text = "".join(b["text"] for b in blocks if b["type"] == "text")
            uses = [b for b in blocks if b["type"] == "tool_use"]
            if resp.stop_reason != "tool_use" or not uses:
                break
            results = []
            for u in uses:
                if on_tool:
                    on_tool(u["name"], u["input"])
                try:
                    out = json.dumps(run_tool(self.inv, u["name"], u["input"]), default=str)
                except Exception as e:  # tool errors go back to Claude instead of crashing the chat
                    out = json.dumps({"error": str(e)})
                calls.append({"tool": u["name"], "input": u["input"]})
                results.append({"type": "tool_result", "tool_use_id": u["id"], "content": out[:MAX_RESULT_CHARS]})
            messages.append({"role": "user", "content": results})
        else:
            text += "\n\n_(Stopped after the maximum number of tool calls.)_"
        self.history += [{"role": "user", "content": question}, {"role": "assistant", "content": text or "(no answer)"}]
        return {"text": text, "tool_calls": calls, "citations": check_citations(text, self.inv)}
