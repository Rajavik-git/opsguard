"""Tool execution layer: scope enforcement, untrusted-data sanitisation, audit trail."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..guardrails import GuardEvent, Guardrails
from ..rag import BM25Retriever, Chunk
from .k8s import TOOL_SPECS, ClusterBackend


@dataclass
class ToolAudit:
    tool: str
    args: dict
    allowed: bool
    output_chars: int


@dataclass
class ToolRegistry:
    cluster: ClusterBackend
    retriever: BM25Retriever
    guards: Guardrails
    audit: list[ToolAudit] = field(default_factory=list)
    events: list[GuardEvent] = field(default_factory=list)
    retrieved: dict[str, Chunk] = field(default_factory=dict)  # citation -> chunk

    specs = TOOL_SPECS

    @property
    def known_citations(self) -> set[str]:
        return set(self.retrieved)

    def _raw(self, name: str, args: dict) -> str:
        if name == "list_pods":
            return self.cluster.list_pods(args["namespace"])
        if name == "get_events":
            return self.cluster.get_events(args["namespace"])
        if name == "get_pod_logs":
            return self.cluster.get_pod_logs(args["namespace"], args["pod"], int(args.get("tail", 50)))
        if name == "describe_deployment":
            return self.cluster.describe_deployment(args["namespace"], args["name"])
        if name == "search_runbooks":
            hits = self.retriever.search(args["query"], k=3)
            out = []
            for chunk, score in hits:
                self.retrieved[chunk.id] = chunk
                out.append(f"### {chunk.citation} {chunk.title} — {chunk.section} (score {score:.2f})\n{chunk.text}")
            return "\n\n".join(out) or "no runbook found"
        raise KeyError(name)

    def execute(self, name: str, args: dict) -> str:
        if name not in {s.name for s in self.specs}:
            self.audit.append(ToolAudit(name, args, False, 0))
            self.events.append(GuardEvent("tool_scope", "blocked", f"outil inconnu '{name}'"))
            return f"ERROR: tool '{name}' does not exist. Available: {[s.name for s in self.specs]}"
        if ev := self.guards.check_tool_scope(name, args):
            self.audit.append(ToolAudit(name, args, False, 0))
            self.events.append(ev)
            return f"ERROR: access denied — {ev.detail}"
        try:
            raw = self._raw(name, args)
        except Exception as e:  # tool errors are returned to the model, not raised
            raw = f"ERROR: {type(e).__name__}: {e}"
        self.audit.append(ToolAudit(name, args, True, len(raw)))
        clean, evs = self.guards.sanitize_untrusted(raw, source=name)
        self.events.extend(evs)
        return clean
