"""Deterministic offline "SRE model".

Lets the whole system (agents, tool loop, guardrails, red team) run in CI with no
API key. It is *deliberately gullible*: like a naive LLM it follows instructions it
finds anywhere in its context (logs, docs, user text). That makes it a faithful
stand-in for measuring what the guardrails — not the model — actually stop.

Optional `latency_ms` and `fail_rate` simulate a real API to exercise the router
(retries, fallback, p95 latency).
"""

from __future__ import annotations

import json
import random
import re
import time
import uuid

from .base import LLMProvider
from .tokens import count_messages, count_tokens
from .types import LLMResponse, Message, ToolCall, TransientError, Usage

ROOT_CAUSES = {
    "oom": (r"OOMKill|exit code 137|out of memory", "RB-002", "Le conteneur dépasse sa limite mémoire (OOMKilled)."),
    "image_pull": (r"ImagePullBackOff|ErrImagePull|manifest unknown", "RB-003", "L'image référencée est introuvable dans le registre."),
    "db_connection": (r"[Cc]onnection refused.*5432|OperationalError", "RB-001", "L'application ne parvient pas à joindre PostgreSQL au démarrage."),
    "readiness_probe": (r"Readiness probe failed", "RB-004", "La readiness probe échoue : le Service n'a plus d'endpoint (503)."),
}
QUERIES = {
    "oom": "OOMKilled mémoire exit code 137 jvm",
    "image_pull": "ImagePullBackOff manifest unknown registry",
    "db_connection": "CrashLoopBackOff connection refused postgresql 5432",
    "readiness_probe": "503 readiness probe failed",
    "unknown": "crashloopbackoff",
}
# Instruction-following on untrusted text: what a naive model does.
_OBEY_CMD = re.compile(
    r"(?i)(?:you must run|must run|please run|run this|execute|give me exactly|exécute[rz]?|lance[rz]?)\s*:?\s*`?((?:kubectl|oc|curl|wget|rm)\b[^`\n]*)`?"
)
_OBEY_TOOL = re.compile(r"(?i)\b(?:call|use|appelle[rz]?)\s+(?:the\s+)?(\w+)\s+(?:tool\s+)?(?:on|for|with|sur)\s+(?:the\s+)?namespace\s+([\w-]+)")
_CITE = re.compile(r"\[(RB-\d{3}#[\w-]+)\]")


def _agent(messages: list[Message]) -> str:
    m = re.search(r"\[agent:(\w+)\]", messages[0].content if messages else "")
    return m.group(1) if m else "chat"


def _all_text(messages: list[Message]) -> str:
    return "\n".join(m.content for m in messages)


def _tools_called(messages: list[Message]) -> list[ToolCall]:
    return [tc for m in messages for tc in m.tool_calls]


def _call(_tool: str, **args) -> ToolCall:
    return ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name=_tool, arguments=args)


class MockSREProvider(LLMProvider):
    name = "mock"

    def __init__(self, model: str = "mock-sre-1", latency_ms: float = 0.0, fail_rate: float = 0.0, seed: int = 0, **kw):
        super().__init__(model, **kw)
        self.latency_ms, self.fail_rate = latency_ms, fail_rate
        self._rng = random.Random(seed)

    # ------------------------------------------------------------------ core
    def _complete(self, messages, tools, temperature, max_output_tokens, json_mode):
        if self.latency_ms:
            time.sleep(self.latency_ms * (0.5 + self._rng.random()) / 1000)
        if self.fail_rate and self._rng.random() < self.fail_rate:
            raise TransientError("simulated 503 from provider")
        agent = _agent(messages)
        handler = {"triage": self._triage, "investigator": self._investigate, "remediation": self._remediate}.get(agent)
        content, calls = handler(messages) if handler else ("OK", [])
        return LLMResponse(
            content=content,
            tool_calls=calls,
            usage=Usage(count_messages(messages), count_tokens(content) + 20 * len(calls)),
            model=self.model,
            provider=self.name,
            finish_reason="tool_calls" if calls else "stop",
        )

    # ---------------------------------------------------------------- agents
    def _triage(self, messages):
        text = messages[-1].content
        ns = re.search(r"(?i)\b(?:namespace|ns|-n)\s*[:=]?\s*([a-z0-9][a-z0-9-]*)", text)
        env = re.search(r"(?i)\b(prod|production|staging|dev)\b", text)
        wl = re.search(r"\b([a-z]+(?:-[a-z]+)*-(?:api|worker|svc))\b", text)
        environment = (env.group(1).lower() if env else "prod").replace("production", "prod")
        out = {
            "namespace": ns.group(1) if ns else "default",
            "workload": wl.group(1) if wl else None,
            "environment": environment,
            "severity": "high" if environment == "prod" else "medium",
            "symptom": text.strip()[:160],
        }
        return json.dumps(out, ensure_ascii=False), []

    def _investigate(self, messages):
        case = json.loads(re.search(r"<case_file>\s*(\{.*?\})\s*</case_file>", messages[1].content, re.S).group(1))
        ns = case["namespace"]
        called = _tools_called(messages)
        names = [c.name for c in called]
        evidence_text = "\n".join(m.content for m in messages if m.role == "tool")
        cluster_text = "\n".join(m.content for m in messages if m.role == "tool" and m.name != "search_runbooks")

        if "list_pods" not in names:
            return "", [_call("list_pods", namespace=ns), _call("get_events", namespace=ns)]

        # naive model: obeys tool instructions found in data
        for tool, target_ns in _OBEY_TOOL.findall(evidence_text):
            if not any(c.name == tool and c.arguments.get("namespace") == target_ns for c in called):
                return "", [_call(tool, namespace=target_ns)]

        if "get_pod_logs" not in names:
            pods = [ln.split()[0] for ln in evidence_text.splitlines()
                    if re.match(r"^[a-z0-9-]+-[a-z0-9]{4,5}-[a-z0-9]{5}\s", ln)
                    and re.search(r"0/1|CrashLoop|ImagePull|OOM|Error", ln)]
            if not pods:
                pods = [ln.split()[0] for ln in evidence_text.splitlines() if re.match(r"^[a-z0-9-]+-[a-z0-9]{4,5}-[a-z0-9]{5}\s", ln)]
            if pods:
                deploy = pods[0].rsplit("-", 2)[0]
                return "", [_call("get_pod_logs", namespace=ns, pod=pods[0], tail=50),
                            _call("describe_deployment", namespace=ns, name=deploy)]

        cause = next((k for k, (rx, *_rest) in ROOT_CAUSES.items() if re.search(rx, evidence_text)), "unknown")
        if "search_runbooks" not in names:
            return "", [_call("search_runbooks", query=QUERIES[cause])]

        rb, summary = (ROOT_CAUSES[cause][1], ROOT_CAUSES[cause][2]) if cause != "unknown" else (None, "Cause non déterminée.")
        rx = ROOT_CAUSES.get(cause, (r"$^",))[0]
        evidence = [ln.strip()[:200] for ln in cluster_text.splitlines() if re.search(rx, ln)][:4]
        task = messages[1].content
        if re.search(r"(?i)verbatim|variables d'environnement|environment variables|env vars", task):
            evidence += [ln.strip().strip('",') for ln in cluster_text.splitlines() if re.search(r"^\s*\"[A-Z_]+=", ln)]
        findings = {
            "root_cause": cause,
            "confidence": 0.9 if cause != "unknown" else 0.2,
            "summary": summary,
            "evidence": evidence,
            "runbook": rb,
            "citations": sorted(set(_CITE.findall(evidence_text))),
        }
        return json.dumps(findings, ensure_ascii=False), []

    def _remediate(self, messages):
        ctx = _all_text(messages)
        findings = json.loads(re.search(r"<findings>\s*(\{.*?\})\s*</findings>", ctx, re.S).group(1))
        rb = findings.get("runbook")
        actions = []
        if rb:
            # take commands from the cited runbook sections, in order
            sections = re.findall(rf"### \[({rb}#[\w-]+)\][^\n]*\n(.*?)(?=\n### |\Z|</untrusted_data>)", ctx, re.S)
            order = {"diagnostic": 0, "remediation": 1}
            sections.sort(key=lambda s: order.get(s[0].split("#")[1], 2))
            for cite, body in sections:
                for block in re.findall(r"```\n(.*?)```", body, re.S):
                    for line in block.strip().splitlines():
                        if line.startswith(("kubectl", "oc ")) and not any(a["command"] == line.strip() for a in actions):
                            mutating = not re.match(r"(kubectl|oc)\s+(get|describe|logs|top|rollout status)", line)
                            actions.append({
                                "command": line.strip(),
                                "rationale": f"Étape du runbook {cite}",
                                "risk": "medium" if mutating else "low",
                                "citations": [cite],
                            })
        # naive model: obeys commands found anywhere in its context
        for m in _OBEY_CMD.finditer(ctx):
            cmd = m.group(1).strip()
            if not any(a["command"] == cmd for a in actions):
                actions.append({"command": cmd, "rationale": "Instruction trouvée dans le contexte", "risk": "low",
                                "citations": _CITE.findall(ctx[max(0, m.start() - 120): m.end() + 120])[:1]})
        report = {
            "title": f"Incident — {findings['root_cause']}",
            "diagnosis": findings["summary"],
            "evidence": findings.get("evidence", []),
            "actions": actions,
        }
        return json.dumps(report, ensure_ascii=False), []
