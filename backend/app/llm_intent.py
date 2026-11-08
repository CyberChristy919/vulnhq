"""Ask a local AI model (Ollama) to pick the question type when keywords can't.

The model only picks an intent and pulls out details (department, package, days).
It never sees the findings and never produces a number; the code still calculates everything.
If Ollama isn't running, is too slow, or replies with something unexpected, classify() returns None
and the keyword answer stands.
"""

import json
import os

import httpx

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "granite4.2:8b")
TIMEOUT_SECONDS = 30

# The 10 question types the code knows how to answer, with a plain description for the model
INTENTS = {
    "critical_assets": "which assets have critical (CVSS 9.0 or higher) unpatched CVEs",
    "top_asset": "the single highest-risk server or asset, and why",
    "patch_first": "which software package to patch first to reduce the most exposure",
    "department_kev": "how many assets in one named department have actively exploited (CISA KEV) vulnerabilities",
    "kev_past_due": "assets with a CISA KEV due date that has already passed",
    "posture": "a short overall summary of vulnerability posture for leadership",
    "bu_exposure": "which business unit or department has the most critical exposure",
    "patch_impact": "how much patching one named software package would reduce the CVE count",
    "network_cves": "CVEs on network devices (routers, switches, firewalls) sorted by CVSS",
    "stale_high": "assets not scanned in a number of days that also have high-severity CVEs",
}


def build_schema(departments, packages):
    """JSON schema Ollama must follow. "none" means not asked, or not one of the 10 types."""
    return {
        "type": "object",
        "properties": {
            "intent": {"type": "string", "enum": list(INTENTS) + ["none"]},
            "department": {"type": "string", "enum": list(departments) + ["none"]},
            "package": {"type": "string", "enum": list(packages) + ["none"]},
            "days": {"type": "integer"},
        },
        "required": ["intent", "department", "package", "days"],
    }


def build_prompt():
    """Instructions for the model: pick one question type, or "none"."""
    lines = [f"- {name}: {desc}" for name, desc in INTENTS.items()]
    return (
        "You route questions for a vulnerability management tool. Pick the ONE question type "
        "that best matches the user's question, or \"none\" if none fit.\n"
        + "\n".join(lines)
        + "\nAlso fill in the department and software package the question names (or \"none\"), "
        "and the number of days it mentions (or 0). Do not answer the question."
    )


def parse_reply(text, departments, packages):
    """Check the model's JSON. Returns a clean dict, or None if it can't be trusted."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("intent") not in INTENTS:
        return None
    intent = data["intent"]
    # Keep only values that really exist in the data
    department = data.get("department") if data.get("department") in departments else None
    package = data.get("package") if data.get("package") in packages else None
    days = data.get("days")
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 3650:
        days = None
    # A question about one department or package needs a name; without one, use the fleet-wide version
    if intent == "department_kev" and department is None:
        intent = "bu_exposure"
    if intent == "patch_impact" and package is None:
        intent = "patch_first"
    return {"intent": intent, "department": department, "package": package, "days": days}


def classify(question, departments, packages):
    """Ask Ollama for the question type. None if Ollama is down, slow, or unsure."""
    body = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": build_prompt()},
            {"role": "user", "content": question},
        ],
        "format": build_schema(departments, packages),
        "stream": False,
        "think": False,
        "options": {"temperature": 0},
        # Keep the model loaded for 30 minutes so demo questions don't wait for it to start
        "keep_alive": "30m",
    }
    try:
        reply = httpx.post(f"{OLLAMA_URL}/api/chat", json=body, timeout=TIMEOUT_SECONDS)
        reply.raise_for_status()
        return parse_reply(reply.json()["message"]["content"], departments, packages)
    except (httpx.HTTPError, KeyError, TypeError, ValueError):
        return None