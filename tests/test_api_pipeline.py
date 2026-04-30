"""Phase 3 (API) integration tests."""
from pathlib import Path

import pytest

from ai_firewall.approval.cli_prompt import auto_approve, auto_deny
from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.core.guard import Blocked, Guard
from ai_firewall.engine import intent as intent_mod


def _evaluate(action: Action, tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", approval_fn=auto_deny)
    return g.evaluate(action)


def test_get_classified_as_api_read():
    assert intent_mod.classify(Action.api("GET", "https://x.com/y")) is IntentType.API_READ


def test_post_classified_as_api_write():
    assert intent_mod.classify(Action.api("POST", "https://x.com/y")) is IntentType.API_WRITE


def test_delete_classified_as_api_destructive():
    assert intent_mod.classify(Action.api("DELETE", "https://x.com/y")) is IntentType.API_DESTRUCTIVE


def test_get_clean_url_allow(tmp_path: Path):
    decision = _evaluate(Action.api("GET", "https://api.example.com/data"), tmp_path)
    assert decision.decision == "ALLOW"
    assert decision.risk == RiskLevel.LOW


def test_metadata_get_bumps_to_critical(tmp_path: Path):
    # SSRF / cloud-metadata exfil → CRITICAL even on a GET.
    decision = _evaluate(Action.api("GET", "http://169.254.169.254/latest/meta-data/"), tmp_path)
    assert decision.risk == RiskLevel.CRITICAL
    assert decision.decision == "REQUIRE_APPROVAL"


def test_private_get_bumps_to_high(tmp_path: Path):
    decision = _evaluate(Action.api("GET", "http://10.0.0.5/internal"), tmp_path)
    assert decision.risk == RiskLevel.HIGH
    assert decision.decision == "REQUIRE_APPROVAL"


def test_post_baseline_requires_approval_on_medium(tmp_path: Path):
    # api_write threshold = MEDIUM, baseline POST risk = MEDIUM.
    decision = _evaluate(Action.api("POST", "https://api.example.com/things"), tmp_path)
    assert decision.decision == "REQUIRE_APPROVAL"


def test_delete_always_requires_approval(tmp_path: Path):
    decision = _evaluate(Action.api("DELETE", "https://api.example.com/things/42"), tmp_path)
    assert decision.decision == "REQUIRE_APPROVAL"


def test_creds_in_url_bumps_risk(tmp_path: Path):
    decision = _evaluate(Action.api("GET", "https://user:pw@api.example.com/x"), tmp_path)
    assert decision.risk >= RiskLevel.HIGH


def test_secrets_in_query_bumps_risk(tmp_path: Path):
    decision = _evaluate(Action.api("GET", "https://api.example.com/x?api_key=abc"), tmp_path)
    assert decision.risk >= RiskLevel.HIGH


def test_approved_request_runs_through_analyze_adapter(tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", approval_fn=auto_approve)
    res = g.execute(Action.api("DELETE", "https://api.example.com/things/42"))
    assert res.decision.decision == "REQUIRE_APPROVAL"
    assert res.execution.exit_code == 0
    assert res.execution.executed is False  # analyze-only never fires the request
    assert "approved (analyze-only)" in res.execution.stdout


def test_audit_records_api_action(tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", approval_fn=auto_approve)
    g.execute(Action.api("GET", "https://api.example.com/users"))
    import json
    rec = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip())
    assert rec["type"] == "api"
    assert rec["intent"] == "API_READ"
    assert rec["rendered"] == "GET https://api.example.com/users"
    assert rec["executed"] is False


def test_post_with_aws_key_in_body_critical(tmp_path: Path):
    body = '{"data": "...", "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"}'
    decision = _evaluate(Action.api("POST", "https://api.example.com/log", body=body), tmp_path)
    assert decision.risk == RiskLevel.CRITICAL
    assert any("AWS access key id" in f for f in decision.impact.code_findings)


def test_post_with_github_token_in_authorization_header_critical(tmp_path: Path):
    headers = {"Authorization": "Bearer ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
    decision = _evaluate(
        Action.api("POST", "https://api.example.com/things", body="{}", headers=headers),
        tmp_path,
    )
    assert decision.risk == RiskLevel.CRITICAL
    assert any("GitHub PAT" in f for f in decision.impact.code_findings)


def test_post_with_jwt_only_high_not_critical(tmp_path: Path):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature_part_here_long_enough"
    decision = _evaluate(
        Action.api("POST", "https://api.example.com/x", body=f'{{"token":"{jwt}"}}'),
        tmp_path,
    )
    # JWTs are only "major" severity → bumps risk to HIGH but not CRITICAL.
    assert decision.risk == RiskLevel.HIGH


def test_safe_post_body_stays_baseline(tmp_path: Path):
    decision = _evaluate(
        Action.api("POST", "https://api.example.com/log", body='{"event":"login","user_id":123}'),
        tmp_path,
    )
    # No secrets → baseline POST risk is MEDIUM, which still requires approval per default rules.
    assert decision.risk == RiskLevel.MEDIUM
