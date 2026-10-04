"""Optional executive summary via an OpenAI-compatible API. No key = feature silently off."""

from __future__ import annotations

import json
import os
import urllib.request

SYSTEM = ("You are a SOC analyst. Write a short incident summary (max 120 words) for a non-technical manager, "
          "then 3 prioritised next steps. Use only the findings provided; do not invent facts.")


def summarize(findings_text: str, timeout: float = 30.0) -> str | None:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        return None
    base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    body = {"model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"), "temperature": 0.2,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": findings_text[:8000]}]}
    req = urllib.request.Request(f"{base}/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        return f"(LLM summary unavailable: {exc.__class__.__name__})"
