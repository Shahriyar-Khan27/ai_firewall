from __future__ import annotations

from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.engine import intent as intent_mod
from ai_firewall.engine.impact import Impact


def score(action: Action, intent: IntentType, flags: dict[str, bool] | None = None) -> RiskLevel:
    """Assign a RiskLevel given the action, its intent, and feature flags."""
    if flags is None:
        flags = intent_mod.feature_flags(action)

    if flags.get("sudo_or_admin"):
        return RiskLevel.CRITICAL

    # Obfuscated commands (base64 / hex / printf-decoded payloads) get a
    # baseline HIGH risk regardless of inner intent — even if the decoded
    # command turned out to be benign, the obfuscation itself is suspicious.
    obfuscation_baseline = RiskLevel.HIGH if flags.get("obfuscation_detected") else RiskLevel.LOW

    base = _base_score(intent, flags)
    return RiskLevel(max(base, obfuscation_baseline))


def _base_score(intent: IntentType, flags: dict[str, bool]) -> RiskLevel:
    """Risk based on intent + flags only, before obfuscation baseline applies."""
    if intent is IntentType.FILE_DELETE:
        if flags.get("system_path"):
            return RiskLevel.CRITICAL
        if flags.get("recursive") and flags.get("wildcard"):
            return RiskLevel.HIGH
        if flags.get("recursive"):
            return RiskLevel.HIGH
        if flags.get("wildcard"):
            return RiskLevel.MEDIUM
        return RiskLevel.MEDIUM

    if intent is IntentType.CODE_MODIFY:
        return RiskLevel.MEDIUM

    if intent is IntentType.FILE_WRITE:
        if flags.get("system_path"):
            return RiskLevel.HIGH
        return RiskLevel.LOW

    if intent is IntentType.FILE_READ:
        return RiskLevel.LOW

    if intent is IntentType.SHELL_EXEC:
        if flags.get("system_path"):
            return RiskLevel.HIGH
        return RiskLevel.MEDIUM

    if intent is IntentType.DB_READ:
        return RiskLevel.LOW
    if intent is IntentType.DB_WRITE:
        return RiskLevel.MEDIUM
    if intent is IntentType.DB_DESTRUCTIVE:
        return RiskLevel.HIGH

    if intent is IntentType.API_READ:
        return RiskLevel.LOW
    if intent is IntentType.API_WRITE:
        return RiskLevel.MEDIUM
    if intent is IntentType.API_DESTRUCTIVE:
        return RiskLevel.HIGH

    return RiskLevel.MEDIUM


def apply_impact(base: RiskLevel, impact: Impact) -> RiskLevel:
    """Bump risk based on impact findings discovered after the initial score."""
    risk = base

    # Code-level findings: anything tagged in code_findings raises at least MEDIUM.
    if impact.code_findings:
        risk = max(risk, RiskLevel.MEDIUM)
        # Hard signals — auth touches, removed functions/tests, syntax errors,
        # destructive SQL — share the same severity ladder.
        major_signals = (
            "removes test",
            "removes function",
            "removes class",
            "sensitive identifiers",
            "syntax errors",
            "replaces file with empty",
            # SQL signals:
            "without WHERE",
            "DROP",
            "TRUNCATE",
            "irreversible schema change",
            "privilege change",
            "multiple statements",
            # URL / API signals:
            "private/loopback",
            "credentials in userinfo",
            "secrets in query string",
            "non-HTTP scheme",
            "destructive-sounding URL path",
            "possible secret in payload",
        )
        critical_signals = (
            "DROP DATABASE",
            "DROP SCHEMA",
            "DELETE without WHERE",
            "UPDATE without WHERE",
            "cloud metadata endpoint",
            "high-confidence secret leak",
        )
        for finding in impact.code_findings:
            if any(sig in finding for sig in critical_signals):
                risk = max(risk, RiskLevel.CRITICAL)
                break
            if any(sig in finding for sig in major_signals):
                risk = max(risk, RiskLevel.HIGH)

    # Git signals: deleting tracked files with uncommitted work, or writing
    # over modified files, is HIGH at minimum.
    if impact.git:
        if impact.git.get("uncommitted_changes"):
            risk = max(risk, RiskLevel.HIGH)
        if impact.git.get("untracked"):
            risk = max(risk, RiskLevel.MEDIUM)

    # Very large blast radius: many files or many MB.
    if impact.files_affected >= 50:
        risk = max(risk, RiskLevel.HIGH)
    if impact.bytes_affected >= 100 * 1024 * 1024:  # 100 MB
        risk = max(risk, RiskLevel.HIGH)

    return RiskLevel(risk)
