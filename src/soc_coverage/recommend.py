"""Guarded AI-generated detection recommendations with deterministic fallback.

The analyzer decides coverage gaps deterministically; the LLM can only draft a suggestion for
candidate gaps after they are identified. Every accepted output is Pydantic-validated,
restricted to declared log sources, and marked for human review.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from .attack import Technique
from .coverage import TechniqueResult


class Recommendation(BaseModel):
    technique_id: str
    detection_idea: str = Field(min_length=20)
    required_log_sources: list[str] = Field(min_length=1)
    suggested_test: str = Field(min_length=10)
    false_positive_notes: str = ""
    needs_human_review: bool = True


SYSTEM = (
    "You are a detection engineer. Propose ONE practical detection idea for the given ATT&CK technique. "
    "Use ONLY the log sources listed as available. Reply with a single JSON object with keys: "
    "technique_id, detection_idea, required_log_sources (subset of the available list), suggested_test, "
    "false_positive_notes. No prose outside the JSON."
)


def build_prompt(tech: Technique, res: TechniqueResult) -> str:
    return (
        f"Technique: {tech.attack_id} {tech.name}\n"
        f"Technique description: {tech.description or tech.name}\n"
        f"Tactics: {', '.join(tech.tactics)}\n"
        f"Available log sources: {', '.join(res.matching_log_sources)}\n"
        "Existing Wazuh rules for this technique: none.\n"
        f"{SYSTEM}"
    )


def _ollama_generate(prompt: str) -> str:
    model = os.environ.get("OLLAMA_MODEL", "llama3.1")
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    payload = {
        "model": model,
        "prompt": prompt,
        "format": "json",
        "stream": False,
    }
    req = urllib.request.Request(
        f"{base.rstrip('/')}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        data = json.loads(response.read().decode("utf-8"))
    text = data.get("response")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Ollama returned an empty response")
    return text.strip()


def validate(raw_json: str, res: TechniqueResult) -> Recommendation | None:
    """Return a validated Recommendation or None if the model broke a guardrail."""
    try:
        text = raw_json.strip().removeprefix("```json").removesuffix("```").strip()
        rec = Recommendation(**json.loads(text))
    except (json.JSONDecodeError, ValidationError, TypeError):
        return None
    if rec.technique_id != res.attack_id:
        return None
    allowed = {s.lower() for s in res.matching_log_sources}
    if not {s.lower() for s in rec.required_log_sources} <= allowed:
        return None
    rec.needs_human_review = True
    return rec


def generate(tech: Technique, res: TechniqueResult, retries: int = 1, provider: str | None = None, client: Any | None = None) -> Recommendation | None:
    """Call the selected AI provider or fall back to deterministic output."""
    provider_name = (provider or os.environ.get("SOC_LLM_PROVIDER", "ollama")).lower()
    prompt = build_prompt(tech, res)
    for _ in range(retries + 1):
        if provider_name == "anthropic":
            if client is None:
                import anthropic
                client = anthropic.Anthropic()
            model = os.environ.get("SOC_LLM_MODEL", "claude-sonnet-5-5")
            msg = client.messages.create(model=model, max_tokens=800, system=SYSTEM,
                                         messages=[{"role": "user", "content": prompt}])
            parts: list[str] = []
            for block in getattr(msg, "content", []):
                if getattr(block, "type", None) == "text":
                    parts.append(getattr(block, "text", ""))
                elif isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
            rec = validate("".join(parts), res)
            if rec:
                return rec
        elif provider_name == "ollama":
            try:
                rec = validate(_ollama_generate(prompt), res)
                if rec:
                    return rec
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        else:
            raise ValueError(f"Unsupported LLM provider '{provider_name}'")
    return None


def deterministic(tech: Technique, res: TechniqueResult) -> Recommendation:
    """Produce an offline-safe draft when no API key or provider is available."""
    source = res.matching_log_sources[0] if res.matching_log_sources else "declared telemetry"
    return Recommendation(
        technique_id=tech.attack_id,
        detection_idea=(
            f"Create a rule that correlates ATT&CK-relevant events for {tech.name} "
            f"from {source} and alerts on repeated or high-confidence activity."
        ),
        required_log_sources=res.matching_log_sources or [source],
        suggested_test=f"Generate a controlled {tech.name} test event in a lab and verify the alert.",
        false_positive_notes="Offline deterministic draft; tune thresholds and validate with an analyst.",
    )


def recommend(tech: Technique, res: TechniqueResult, use_ai: bool = True, provider: str | None = None) -> Recommendation:
    """Return a guarded AI recommendation or a deterministic offline draft."""
    provider_name = (provider or os.environ.get("SOC_LLM_PROVIDER", "ollama")).lower()
    if use_ai:
        if provider_name == "anthropic" and os.environ.get("ANTHROPIC_API_KEY"):
            try:
                result = generate(tech, res, provider=provider_name)
                if result is not None:
                    return result
            except (ImportError, OSError, ValueError):
                pass
        elif provider_name == "ollama":
            try:
                result = generate(tech, res, provider=provider_name)
                if result is not None:
                    return result
            except (OSError, ValueError):
                pass
    return deterministic(tech, res)
