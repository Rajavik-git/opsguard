import pytest

from opsguard.agents.context import ContextBudget, compact_history, evidence_digest
from opsguard.llm import LLMRouter, Message, MockSREProvider
from opsguard.rag import BM25Retriever, load_runbooks
from opsguard.runtime import build_orchestrator, default_incident


def _run(cfg, scenario, guardrails=True):
    orch = build_orchestrator(cfg, scenario, guardrails_enabled=guardrails, router=LLMRouter([MockSREProvider()]))
    return orch.run(default_incident(scenario))


@pytest.mark.parametrize("name", ["payments-crashloop", "checkout-oom", "reporting-imagepull", "gateway-readiness"])
def test_diagnosis_matches_expected(cfg, all_scenarios, name):
    s = all_scenarios[name]
    report = _run(cfg, s)
    assert report.status == "resolved_plan", report.error
    assert report.findings["root_cause"] == s["expected"]["root_cause"]
    assert report.actions, "a remediation plan is expected"
    assert not report.blocked_actions, "legitimate runbook actions must not be blocked"
    # every mutating action is gated and cites the expected runbook
    for a in report.actions:
        if a["decision"] == "require_approval":
            assert any(c.startswith(s["expected"]["runbook"]) for c in a["citations"])


def test_report_markdown_and_telemetry(cfg, all_scenarios):
    r = _run(cfg, all_scenarios["payments-crashloop"])
    md = r.to_markdown()
    assert "rollout undo" in md and "require_approval" in md
    assert r.telemetry["calls"] >= 4 and r.telemetry["input_tokens"] > 0


def test_rag_retrieves_right_runbook(cfg):
    rag = BM25Retriever(load_runbooks(cfg["paths"]["runbooks"]))
    top = rag.search("pod OOMKilled exit code 137", k=1)[0][0]
    assert top.runbook_id == "RB-002"
    assert rag.search("readiness probe 503", k=1)[0][0].runbook_id == "RB-004"


def test_evidence_digest_dedupes_and_filters():
    logs = "INFO ok\nERROR refused 1\nERROR refused 2\nINFO fine"
    assert evidence_digest(logs) == "ERROR refused 1"


def test_history_compaction():
    msgs = [Message("system", "s"), Message("user", "u")] + [
        Message("tool", "INFO " * 500 + "\nERROR boom", name="get_pod_logs") for _ in range(10)
    ]
    out = compact_history(msgs, ContextBudget(total=800, keep_last_turns=2))
    assert out[2].content.startswith("[compacted]") and "ERROR boom" in out[2].content
    assert out[-1].content == msgs[-1].content
