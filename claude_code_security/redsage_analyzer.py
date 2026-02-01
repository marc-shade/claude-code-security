"""
RedSage Analyzer: Local LLM-powered deep threat analysis. [Tier 2+]

Integrates with a local RedSage Q4_K_M cluster (4x llama-server behind Nginx)
for deep content analysis beyond pattern matching. RedSage is a cybersecurity-
tuned Qwen3-8B model running on Apple Silicon with Metal GPU acceleration.

Architecture:
    Nginx (port 8800) -> 4x llama-server instances (ports 8801-8804)
    Each instance: Q4_K_M quantized, --parallel 4, Metal GPU, 8192 ctx

When enabled, adds a Phase 4 scanner to the security gate pipeline:
    Phase 0: (Optional) LLM classifier (fast, binary SAFE/MALICIOUS)
    Phase 1: Injection detection (heuristic patterns)
    Phase 2: Policy check (configurable patterns)
    Phase 3: Threat intelligence (URL/IP/payload)
    Phase 4: RedSage deep analysis (contextual reasoning)

RedSage is invoked only for HIGH+ severity findings from earlier phases,
acting as a second opinion to reduce false positives and provide actionable
context on confirmed threats.
"""

import hashlib
import json
import logging
import time
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple

from claude_code_security import config

logger = logging.getLogger("claude_code_security.redsage_analyzer")

_analysis_cache: Dict[str, Tuple[dict, float]] = {}


ANALYSIS_SYSTEM_PROMPT = (
    "You are RedSage, a cybersecurity threat analysis engine integrated into a "
    "Claude Code security gate. You receive content that has been flagged by "
    "heuristic scanners. Your job is to provide a second opinion.\n\n"
    "Analyze the content and respond with EXACTLY this JSON format:\n"
    '{"verdict": "SAFE|SUSPICIOUS|MALICIOUS", '
    '"confidence": 0.0-1.0, '
    '"category": "injection|exfiltration|c2|exploit|policy|benign", '
    '"reasoning": "one sentence explanation"}\n\n'
    "Be precise. False positives waste human attention. False negatives risk compromise."
)

IOC_EXTRACTION_PROMPT = (
    "You are RedSage, a cyber forensics IOC extraction engine. "
    "Extract all indicators of compromise from the provided text. "
    "Respond with EXACTLY this JSON format:\n"
    '{"iocs": [{"type": "ip|domain|url|hash|cve|email", '
    '"value": "the indicator", '
    '"context": "why it is suspicious"}], '
    '"risk_summary": "one sentence overall assessment"}'
)


def _query_redsage(
    user_content: str,
    system_prompt: str,
    max_tokens: int = 512,
    temperature: float = 0.1,
) -> Optional[dict]:
    """Send a query to the RedSage cluster. Returns parsed JSON or None on failure."""
    payload = json.dumps({
        "model": "redsage",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content[:config.REDSAGE_MAX_INPUT_CHARS]},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": False,
    }).encode("utf-8")

    req = urllib.request.Request(
        config.REDSAGE_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=config.REDSAGE_TIMEOUT_SECONDS) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            # Try to parse as JSON (model may wrap in markdown code blocks)
            content = content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            return json.loads(content)
    except (urllib.error.URLError, ConnectionError) as e:
        logger.debug(f"RedSage cluster unreachable: {e}")
        return None
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        logger.warning(f"RedSage returned non-JSON response: {e}")
        return None
    except Exception as e:
        logger.warning(f"RedSage query failed: {e}")
        return None


def is_available() -> bool:
    """Check if the RedSage cluster is reachable and healthy."""
    if not config.REDSAGE_ENABLED:
        return False
    try:
        req = urllib.request.Request(
            config.REDSAGE_HEALTH_URL,
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("status") == "ok"
    except Exception:
        return False


def analyze_content(
    content: str,
    source: str = "unknown",
    prior_findings: Optional[List[str]] = None,
) -> Optional[dict]:
    """
    Deep analysis of flagged content via RedSage.

    Args:
        content: The text content to analyze
        source: Where the content came from
        prior_findings: Findings from earlier scan phases (for context)

    Returns:
        Dict with keys: verdict, confidence, category, reasoning
        None if RedSage is unavailable or disabled
    """
    if not config.REDSAGE_ENABLED:
        return None

    # Check cache
    content_hash = hashlib.sha256(content[:4000].encode("utf-8")).hexdigest()[:16]
    cached = _analysis_cache.get(content_hash)
    if cached:
        result, ts = cached
        if time.time() - ts < config.REDSAGE_CACHE_TTL:
            logger.debug(f"RedSage cache hit for {content_hash}")
            return result

    # Build context-rich prompt
    prompt_parts = [f"Source: {source}"]
    if prior_findings:
        prompt_parts.append(f"Prior scanner findings: {'; '.join(prior_findings[:5])}")
    prompt_parts.append(f"Content to analyze:\n{content[:config.REDSAGE_MAX_INPUT_CHARS]}")
    user_prompt = "\n\n".join(prompt_parts)

    result = _query_redsage(user_prompt, ANALYSIS_SYSTEM_PROMPT)

    if result and "verdict" in result:
        # Cache valid results
        if len(_analysis_cache) >= config.REDSAGE_CACHE_MAX:
            oldest_key = next(iter(_analysis_cache))
            del _analysis_cache[oldest_key]
        _analysis_cache[content_hash] = (result, time.time())
        return result

    return None


def extract_iocs(text: str, source: str = "unknown") -> Optional[dict]:
    """
    Extract IOCs from text using RedSage's contextual understanding.

    Args:
        text: Raw text (logs, code, etc.) to scan for IOCs
        source: Source description

    Returns:
        Dict with keys: iocs (list), risk_summary (str)
        None if unavailable
    """
    if not config.REDSAGE_ENABLED:
        return None

    prompt = f"Source: {source}\n\nText to analyze:\n{text[:config.REDSAGE_MAX_INPUT_CHARS]}"
    return _query_redsage(prompt, IOC_EXTRACTION_PROMPT, max_tokens=1024)
