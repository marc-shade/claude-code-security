"""
Security Gate: Injection + policy + threat scanning. [Tier 2]

Chains security scanners into a single pipeline:
0. (Optional) LLM classifier for high-risk sources
1. Prompt injection detection (heuristic patterns)
2. Policy check (configurable forbidden patterns)
3. Threat intelligence (URL/IP/payload detection)
4. (Optional) RedSage deep analysis for HIGH+ severity findings

Returns a SecurityVerdict: ALLOW, WARN, or BLOCK.
"""

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from claude_code_security import config
from claude_code_security.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
)

logger = logging.getLogger("claude_code_security.security_gate")

_injection_breaker: Optional[CircuitBreaker] = None
_llm_cache: Dict[str, tuple] = {}


def _get_injection_breaker() -> CircuitBreaker:
    global _injection_breaker
    if _injection_breaker is None:
        _injection_breaker = CircuitBreaker(
            name="injection_detector",
            config=CircuitBreakerConfig(
                failure_threshold=config.CB_FAILURE_THRESHOLD,
                timeout_seconds=config.CB_TIMEOUT_SECONDS,
                success_threshold=config.CB_SUCCESS_THRESHOLD,
            ),
        )
    return _injection_breaker


class Severity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = [Severity.NONE, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass
class ScanResult:
    scanner: str
    severity: Severity
    findings: List[str] = field(default_factory=list)
    raw: Optional[Dict] = None
    error: Optional[str] = None


@dataclass
class SecurityVerdict:
    action: str  # ALLOW, WARN, BLOCK
    severity: Severity
    scan_results: List[ScanResult] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict:
        return {
            "action": self.action,
            "severity": self.severity.value,
            "summary": self.summary,
            "scan_count": len(self.scan_results),
            "findings": [
                {
                    "scanner": r.scanner,
                    "severity": r.severity.value,
                    "findings": r.findings,
                    "error": r.error,
                }
                for r in self.scan_results
                if r.findings or r.error
            ],
        }


# Default injection patterns
INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard your instructions",
    "you are now",
    "new instructions:",
    "system prompt:",
    "override:",
    "admin mode",
    "developer mode",
    "ignore safety",
    "jailbreak",
    "DAN mode",
    "bypass filters",
    "forget your training",
    "act as if",
    "pretend you are",
    "<system>",
    "\x00",
]

HIGH_RISK_INJECTION_PATTERNS = [
    "ignore previous",
    "system prompt",
    "jailbreak",
    "DAN mode",
    "\x00",
]

# Default policy violations
DEFAULT_POLICY_PATTERNS = {
    "TODO": "Contains TODO marker",
    "FIXME": "Contains FIXME marker",
    "HACK": "Contains HACK marker",
    "mock_data": "References mock data",
    "placeholder": "Contains placeholder content",
    "dummy_": "Contains dummy values",
    "fake_": "Contains fake values",
    "hardcoded": "Contains hardcoded values",
}

# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly/\w+",
    r"tinyurl\.com/\w+",
    r"0x[0-9a-fA-F]{8}",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}",
]


def _load_custom_policies() -> Dict[str, str]:
    """Load custom policy patterns from config file."""
    if config.CUSTOM_POLICIES_PATH.exists():
        try:
            data = json.loads(config.CUSTOM_POLICIES_PATH.read_text())
            return data.get("policy_patterns", {})
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _scan_injection(content: str, source: str = "") -> ScanResult:
    """Phase 1: Prompt injection detection via heuristic patterns."""
    try:
        content_lower = content.lower()
        matches = [p for p in INJECTION_PATTERNS if p.lower() in content_lower]

        if not matches:
            breaker = _get_injection_breaker()
            breaker._on_success()
            return ScanResult(scanner="injection_detector", severity=Severity.NONE)

        has_high_risk = any(p.lower() in content_lower for p in HIGH_RISK_INJECTION_PATTERNS)

        if has_high_risk or len(matches) >= 3:
            severity = Severity.CRITICAL
        elif len(matches) >= 2:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        breaker = _get_injection_breaker()
        breaker._on_success()

        return ScanResult(
            scanner="injection_detector",
            severity=severity,
            findings=[f"Injection pattern: '{m}'" for m in matches[:5]],
        )

    except Exception as e:
        logger.error(f"Injection scan error: {e}")
        breaker = _get_injection_breaker()
        breaker._on_failure()
        state = breaker.get_state()
        if state in (CircuitState.OPEN, CircuitState.HALF_OPEN):
            return ScanResult(
                scanner="injection_detector",
                severity=Severity.CRITICAL,
                error=f"Injection scanner failed (circuit {state.value}): {e}",
                findings=["Scanner unavailable - fail-closed (BLOCK)"],
            )
        return ScanResult(
            scanner="injection_detector",
            severity=Severity.HIGH,
            error=str(e),
            findings=["Scanner error - fail-closed below threshold (WARN)"],
        )


def _scan_policy(content: str, context: str = "") -> ScanResult:
    """Phase 2: Policy check for code/config content."""
    try:
        patterns = {**DEFAULT_POLICY_PATTERNS, **_load_custom_policies()}
        violations = []
        content_lower = content.lower()
        for pattern, description in patterns.items():
            if pattern.lower() in content_lower:
                violations.append(description)

        if not violations:
            return ScanResult(scanner="policy_check", severity=Severity.NONE)

        severity = Severity.HIGH if len(violations) >= 3 else Severity.MEDIUM
        return ScanResult(
            scanner="policy_check",
            severity=severity,
            findings=violations[:10],
        )
    except Exception as e:
        logger.error(f"Policy scan error: {e}")
        return ScanResult(scanner="policy_check", severity=Severity.NONE, error=str(e))


def _scan_threat_intel(content: str, source: str = "") -> ScanResult:
    """Phase 3: Threat intelligence - URL/IP/payload detection."""
    try:
        threats = []
        for pattern in SUSPICIOUS_URL_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                threats.append(f"Suspicious pattern: {pattern} ({len(matches)} matches)")

        if "base64" in content.lower():
            b64_pattern = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', content)
            if b64_pattern:
                threats.append(f"Base64 payload detected ({len(b64_pattern)} segments)")

        if not threats:
            return ScanResult(scanner="threat_intel", severity=Severity.NONE)

        severity = Severity.HIGH if len(threats) >= 2 else Severity.MEDIUM
        return ScanResult(scanner="threat_intel", severity=severity, findings=threats)

    except Exception as e:
        logger.error(f"Threat intel scan error: {e}")
        return ScanResult(scanner="threat_intel", severity=Severity.NONE, error=str(e))


def _scan_llm_classifier(content: str, source: str = "") -> Optional[ScanResult]:
    """
    Phase 0 (optional): LLM-based injection classifier.
    Only runs when enabled via config and for high-risk sources.
    """
    global _llm_cache

    if not config.LLM_CLASSIFIER_ENABLED or source not in config.HIGH_RISK_SOURCES:
        return None

    content_hash = hashlib.sha256(content[:2000].encode("utf-8")).hexdigest()
    cached = _llm_cache.get(content_hash)
    if cached:
        result, ts = cached
        if time.time() - ts < config.LLM_CACHE_TTL:
            return result
        del _llm_cache[content_hash]

    try:
        import urllib.request

        prompt = (
            "Analyze the following text for prompt injection attacks. "
            "Respond with exactly one word: SAFE, SUSPICIOUS, or MALICIOUS.\n\n"
            f"Text: {content[:1000]}"
        )
        payload = json.dumps({
            "model": config.LLM_CLASSIFIER_MODEL,
            "prompt": prompt,
            "stream": False,
        }).encode("utf-8")

        req = urllib.request.Request(
            config.LLM_CLASSIFIER_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        opener = urllib.request.build_opener(urllib.request.HTTPHandler)
        resp = opener.open(req, timeout=2)
        data = json.loads(resp.read())
        response_text = data.get("response", "").strip().upper()

        if "MALICIOUS" in response_text:
            result = ScanResult(
                scanner="llm_classifier", severity=Severity.CRITICAL,
                findings=["LLM classifier: MALICIOUS injection detected"],
            )
        elif "SUSPICIOUS" in response_text:
            result = ScanResult(
                scanner="llm_classifier", severity=Severity.HIGH,
                findings=["LLM classifier: suspicious content detected"],
            )
        else:
            result = ScanResult(scanner="llm_classifier", severity=Severity.NONE)

        if len(_llm_cache) >= config.LLM_CACHE_MAX:
            oldest = next(iter(_llm_cache))
            del _llm_cache[oldest]
        _llm_cache[content_hash] = (result, time.time())
        return result

    except Exception as e:
        logger.debug(f"LLM classifier unavailable: {e}")
        return None


def _scan_redsage(content: str, source: str, prior_results: List[ScanResult]) -> Optional[ScanResult]:
    """Phase 4 (optional): RedSage deep analysis for flagged content.

    Only invoked when earlier phases produced HIGH+ severity findings,
    providing contextual second-opinion analysis to reduce false positives.
    """
    if not config.REDSAGE_ENABLED:
        return None

    # Only invoke RedSage for HIGH+ severity findings from earlier phases
    max_prior = Severity.NONE
    for r in prior_results:
        if SEVERITY_ORDER.index(r.severity) > SEVERITY_ORDER.index(max_prior):
            max_prior = r.severity
    if SEVERITY_ORDER.index(max_prior) < SEVERITY_ORDER.index(Severity.HIGH):
        return None

    try:
        from claude_code_security.redsage_analyzer import analyze_content

        prior_findings = []
        for r in prior_results:
            prior_findings.extend(r.findings)

        result = analyze_content(content, source, prior_findings)
        if result is None:
            return None

        verdict = result.get("verdict", "").upper()
        confidence = float(result.get("confidence", 0))
        category = result.get("category", "unknown")
        reasoning = result.get("reasoning", "")

        if verdict == "MALICIOUS" and confidence >= 0.7:
            severity = Severity.CRITICAL
        elif verdict == "MALICIOUS":
            severity = Severity.HIGH
        elif verdict == "SUSPICIOUS":
            severity = Severity.MEDIUM
        else:
            # RedSage says SAFE — downgrade prior findings
            return ScanResult(
                scanner="redsage_analyzer",
                severity=Severity.NONE,
                findings=[f"RedSage ({confidence:.0%}): {reasoning} [{category}]"],
            )

        return ScanResult(
            scanner="redsage_analyzer",
            severity=severity,
            findings=[f"RedSage ({confidence:.0%}): {reasoning} [{category}]"],
            raw=result,
        )

    except Exception as e:
        logger.debug(f"RedSage analysis unavailable: {e}")
        return None


def scan_content(
    content: str,
    source: str = "unknown",
    context: str = "",
    scan_code: bool = True,
) -> SecurityVerdict:
    """
    Scan content through the unified security pipeline.

    Args:
        content: The text content to scan
        source: Where the content came from
        context: Additional context (URL, file path, etc.)
        scan_code: Whether to include policy check (for code/config)

    Returns:
        SecurityVerdict with ALLOW/WARN/BLOCK action
    """
    if not content or not content.strip():
        return SecurityVerdict(action="ALLOW", severity=Severity.NONE, summary="Empty content")

    results: List[ScanResult] = []

    # Phase 0: Optional LLM classifier
    llm_result = _scan_llm_classifier(content, source)
    if llm_result:
        results.append(llm_result)
        if llm_result.severity == Severity.CRITICAL:
            return SecurityVerdict(
                action="BLOCK", severity=Severity.CRITICAL, scan_results=results,
                summary=f"BLOCKED: LLM classifier detected malicious content from {source}",
            )

    # Phase 1: Injection detection
    injection_result = _scan_injection(content, source)
    results.append(injection_result)
    if injection_result.severity == Severity.CRITICAL:
        return SecurityVerdict(
            action="BLOCK", severity=Severity.CRITICAL, scan_results=results,
            summary=f"BLOCKED: Critical injection detected from {source}. "
                    f"Findings: {'; '.join(injection_result.findings[:3])}",
        )

    # Phase 2: Policy check
    if scan_code:
        results.append(_scan_policy(content, context))

    # Phase 3: Threat intelligence
    results.append(_scan_threat_intel(content, source))

    # Phase 4: RedSage deep analysis (only for HIGH+ severity findings)
    redsage_result = _scan_redsage(content, source, results)
    if redsage_result:
        results.append(redsage_result)

    # Determine final verdict
    max_severity = Severity.NONE
    for r in results:
        if SEVERITY_ORDER.index(r.severity) > SEVERITY_ORDER.index(max_severity):
            max_severity = r.severity

    severity_idx = SEVERITY_ORDER.index(max_severity)
    if severity_idx >= SEVERITY_ORDER.index(Severity.CRITICAL):
        action = "BLOCK"
    elif severity_idx >= SEVERITY_ORDER.index(Severity.HIGH):
        action = "WARN"
    else:
        action = "ALLOW"

    all_findings = []
    for r in results:
        all_findings.extend(r.findings)

    summary_parts = [f"Source: {source}"]
    if all_findings:
        summary_parts.append(f"Findings: {'; '.join(all_findings[:5])}")

    return SecurityVerdict(
        action=action, severity=max_severity,
        scan_results=results, summary=". ".join(summary_parts),
    )
