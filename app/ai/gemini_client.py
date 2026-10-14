"""
Thin client around the Gemini generateContent API used to turn raw
Semgrep/Gitleaks findings into plain-English explanations and suggested
fixes / patches.
"""

import json
from typing import Any

import requests

from app.config import Config

_SYSTEM_PROMPT = (
    "You are a senior application security engineer. You are given a single "
    "static-analysis finding (from Semgrep or Gitleaks) along with the "
    "surrounding code. Respond ONLY with a JSON object with these keys: "
    '"explanation" (plain-English, 2-3 sentences on why this is a risk), '
    '"severity_assessment" (one of: critical, high, medium, low), '
    '"fixed_code" (the corrected code snippet, same language, minimal diff), '
    '"remediation_notes" (short actionable steps). '
    "No markdown fences, no preamble, JSON only."
)


class GeminiError(Exception):
    pass


def _call_gemini(user_prompt: str) -> str:
    if not Config.GEMINI_API_KEY:
        raise GeminiError("GEMINI_API_KEY is not set. Add it to your .env file.")

    url = (
        f"{Config.GEMINI_API_URL}/{Config.GEMINI_MODEL}:generateContent"
        f"?key={Config.GEMINI_API_KEY}"
    )
    payload = {
        "systemInstruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }

    try:
        response = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=60,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise GeminiError(f"Gemini API request failed: {exc}") from exc

    data = response.json()
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise GeminiError(f"Unexpected Gemini response shape: {data}") from exc


def analyze_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Send one normalized finding to Gemini and return a structured analysis.
    """
    prompt = (
        f"Tool: {finding.get('tool')}\n"
        f"Rule/ID: {finding.get('rule_id')}\n"
        f"Message: {finding.get('message') or finding.get('description')}\n"
        f"File: {finding.get('path')}\n"
        f"Lines: {finding.get('start_line')}-{finding.get('end_line')}\n"
        f"Code:\n{finding.get('code_snippet') or finding.get('match') or ''}\n"
    )

    raw_content = _call_gemini(prompt)
    cleaned = raw_content.strip().removeprefix("```json").removesuffix("```").strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {
            "explanation": raw_content,
            "severity_assessment": "unknown",
            "fixed_code": "",
            "remediation_notes": "Could not parse structured response.",
        }
