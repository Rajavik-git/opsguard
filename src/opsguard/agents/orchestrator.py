"""Multi-agent orchestration: Triage → Investigator (tool loop) → Remediation → Policy gate.

Implemented as an explicit state machine (no framework lock-in): each step is
observable, bounded (max tool steps, token budget, cost budget) and auditable.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field

from ..guardrails import GuardEvent, Guardrails
from ..llm.router import LLMRouter
from ..llm.types import LLMError, Message
from ..tools import ToolRegistry
from . import prompts
from .context import ContextBudget, build_remediation_context, compact_history


def _parse_json(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError(f"no JSON object in model output: {text[:120]!r}")
    return json.loads(m.group(0))


@dataclass
class IncidentReport:
    status: str  # resolved_plan | blocked | error
    case: dict = field(default_factory=dict)
    findings: dict = field(default_factory=dict)
    diagnosis: str = ""
    evidence: list[str] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    blocked_actions: list[str] = field(default_factory=list)
    guard_events: list[GuardEvent] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)
    telemetry: dict = field(default_factory=dict)
    duration_s: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["guard_events"] = [asdict(e) for e in self.guard_events]
        return d

    def to_markdown(self) -> str:
        icon = {"allow": "🟢", "require_approval": "🟠"}
        lines = [f"# Rapport OpsGuard — {self.case.get('namespace', '?')} ({self.case.get('environment', '?')})", ""]
        if self.status == "blocked":
            lines += ["**Requête refusée par les guardrails.**", ""]
        lines += [f"**Diagnostic** : {self.diagnosis or '—'}", ""]
        if self.findings:
            lines += [f"Cause : `{self.findings.get('root_cause')}` · confiance {self.findings.get('confidence')} · runbook {self.findings.get('runbook')}", ""]
        if self.evidence:
            lines += ["## Preuves", *[f"- `{e}`" for e in self.evidence], ""]
        if self.actions:
            lines += ["## Actions proposées (aucune n'est exécutée automatiquement)", ""]
            for i, a in enumerate(self.actions, 1):
                lines.append(f"{i}. {icon.get(a['decision'], '⚪')} `{a['command']}` — {a['decision']} · {', '.join(a.get('citations', []))}")
            lines.append("")
        if self.blocked_actions:
            lines += ["## Actions bloquées par la politique", *[f"- 🔴 {b}" for b in self.blocked_actions], ""]
        if self.guard_events:
            lines += ["## Journal des guardrails", *[f"- [{e.layer}] {e.action} : {e.detail}" for e in self.guard_events], ""]
        t = self.telemetry
        if t:
            lines += [
                "## Coûts & performance",
                f"{t['calls']} appels LLM · {t['input_tokens']}+{t['output_tokens']} tokens · ${t['cost_usd']:.4f} · "
                f"p50 {t['latency_p50_ms']} ms · p95 {t['latency_p95_ms']} ms · {self.duration_s:.2f} s",
            ]
        return "\n".join(lines)


class Orchestrator:
    def __init__(self, router: LLMRouter, tools: ToolRegistry, guards: Guardrails,
                 budget: ContextBudget | None = None, max_tool_steps: int = 8):
        self.router, self.tools, self.guards = router, tools, guards
        self.budget = budget or ContextBudget()
        self.max_tool_steps = max_tool_steps

    # ---------------------------------------------------------------- agents
    def _triage(self, incident: str) -> dict:
        resp = self.router.complete(
            [Message("system", prompts.TRIAGE), Message("user", incident)], agent="triage", json_mode=True
        )
        return _parse_json(resp.content)

    def _investigate(self, incident: str, case: dict) -> tuple[dict, list[str]]:
        messages = [
            Message("system", prompts.INVESTIGATOR),
            Message("user", f"<case_file>\n{json.dumps(case, ensure_ascii=False)}\n</case_file>\n\n<incident>\n{incident}\n</incident>"),
        ]
        outputs: list[str] = []
        for _ in range(self.max_tool_steps):
            resp = self.router.complete(compact_history(messages, self.budget), tools=self.tools.specs, agent="investigator")
            if not resp.tool_calls:
                return _parse_json(resp.content), outputs
            messages.append(Message("assistant", resp.content, tool_calls=resp.tool_calls))
            for tc in resp.tool_calls:
                result = self.tools.execute(tc.name, tc.arguments)
                outputs.append(result)
                messages.append(Message("tool", result, tool_call_id=tc.id, name=tc.name))
        raise LLMError("investigation exceeded max tool steps")

    def _remediate(self, incident: str, findings: dict, outputs: list[str]) -> dict:
        runbooks = "\n\n".join(o for o in outputs if "### [RB-" in o)
        ctx = build_remediation_context(json.dumps(findings, ensure_ascii=False), outputs, runbooks, self.budget)
        resp = self.router.complete(
            [Message("system", prompts.REMEDIATION), Message("user", f"<incident>\n{incident}\n</incident>\n\n{ctx}")],
            agent="remediation", json_mode=True,
        )
        return _parse_json(resp.content)

    # ------------------------------------------------------------------ run
    def run(self, incident: str) -> IncidentReport:
        t0 = time.perf_counter()
        report = IncidentReport(status="resolved_plan")
        try:
            verdict = self.guards.check_input(incident)
            report.guard_events += verdict.events
            if not verdict.allowed:
                report.status = "blocked"
                report.diagnosis = "La requête contient une tentative de contournement des règles de sécurité."
                return report
            incident = verdict.text

            report.case = self._triage(incident)
            report.findings, outputs = self._investigate(incident, report.case)
            plan = self._remediate(incident, report.findings, outputs)

            # ---- output guardrails: secrets, policy, grounding
            diag, evs = self.guards.check_output_text(plan.get("diagnosis", ""))
            report.diagnosis = diag
            report.guard_events += evs
            for e in plan.get("evidence", []):
                clean, evs = self.guards.check_output_text(e)
                report.evidence.append(clean)
                report.guard_events += evs
            env = report.case.get("environment", "prod")
            for action in plan.get("actions", []):
                kept, evs = self.guards.check_action(dict(action), self.tools.known_citations, env)
                report.guard_events += evs
                if kept is None:
                    report.blocked_actions.append(action["command"])
                else:
                    report.actions.append(kept)
        except Exception as e:  # never crash the caller (CLI, MCP, harness)
            report.status, report.error = "error", f"{type(e).__name__}: {e}"
        finally:
            report.guard_events += self.tools.events
            report.tool_calls = [asdict(a) for a in self.tools.audit]
            report.telemetry = self.router.telemetry.summary()
            report.duration_s = time.perf_counter() - t0
        return report
