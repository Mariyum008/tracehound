"""Optional AI narrator: turns verified findings into a plain-English breach story, then checks its citations."""
from __future__ import annotations

import json
import os

from .investigation import Investigation, check_citations

DEFAULT_MODEL = os.environ.get("TRACEHOUND_MODEL", "claude-sonnet-5-5")

SYSTEM_PROMPT = """You are a senior SOC analyst writing an incident narrative from network evidence.
Rules:
- Use ONLY the findings, timeline and evidence provided. Never invent hosts, domains, files or events.
- Cite evidence for every factual claim as [frame N] or [frames N, M] using frame numbers from the data.
- If the evidence does not show something (for example, what malware family it is, or file contents inside
  encrypted traffic), say it cannot be determined from network data alone.
- Separate what is confirmed from what is likely.
Write in Markdown with these sections:
1. Summary (3-4 sentences a manager can read)
2. What happened, step by step (chronological, each step with its MITRE technique and citations)
3. How the attacker got in (initial access, or "not visible in this capture")
4. Affected hosts and indicators of compromise (IPs, domains, URLs)
5. Recommended actions (containment first)
6. Limits of this analysis"""


def build_context(inv: Investigation) -> str:
    # Compact JSON the model reasons over; evidence is pre-rendered so it can quote frames accurately
    data = {
        "overview": inv.overview(),
        "likely_first_compromised_host": inv.patient_zero(),
        "timeline": [{k: v for k, v in e.items() if k != "time"} for e in inv.timeline()],
        "findings": [
            {**{k: v for k, v in f.to_dict().items() if k not in ("first_seen", "last_seen")},
             "evidence": inv.evidence(f.evidence_frames)}
            for f in inv.findings
        ],
    }
    return json.dumps(data, indent=1, default=str)


def narrate(inv: Investigation, model: str = DEFAULT_MODEL, max_tokens: int = 3000, api_key: str | None = None, client=None) -> dict:
    """Ask Claude for the breach story and return it with a citation check."""
    if not inv.findings:
        return {"narrative": "No suspicious activity was detected in this capture, so there is no breach story to tell.",
                "citations": {"ok": True, "cited_frames": [], "nonexistent": [], "outside_evidence": []}}
    if client is None:
        import anthropic  # imported here so the rest of the tool works without the SDK
        client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
    msg = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": "Investigation data:\n```json\n" + build_context(inv) + "\n```\n"
                                              "Write the incident narrative."}],
    )
    text = "".join(block.text for block in msg.content if getattr(block, "type", "") == "text")
    return {"narrative": text, "citations": check_citations(text, inv), "model": model}
