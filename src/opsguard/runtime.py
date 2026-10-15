"""Wiring: config → router, guardrails, RAG, tools, orchestrator."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from .agents import Orchestrator
from .agents.context import ContextBudget
from .guardrails import Guardrails
from .llm import LLMRouter, build_router
from .rag import BM25Retriever, load_runbooks
from .tools import FixtureCluster, KubectlCluster, ToolRegistry, load_scenarios

ROOT = Path(os.environ.get("OPSGUARD_HOME", Path(__file__).resolve().parents[2]))


def load_config(path: str | Path | None = None) -> dict:
    p = Path(path) if path else ROOT / "config" / "opsguard.yaml"
    cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
    cfg["paths"] = {k: str((ROOT / v) if not Path(v).is_absolute() else v) for k, v in cfg["paths"].items()}
    return cfg


def budget_from(cfg: dict) -> ContextBudget:
    c = cfg.get("context", {})
    return ContextBudget(c.get("total_tokens", 6000), c.get("evidence_tokens", 1500),
                         c.get("runbook_tokens", 1500), c.get("keep_last_turns", 4))


def build_orchestrator(
    cfg: dict,
    scenario: dict | None = None,
    guardrails_enabled: bool = True,
    router: LLMRouter | None = None,
    kube_context: str | None = None,
) -> Orchestrator:
    guards = Guardrails(cfg["paths"]["policy"], enabled=guardrails_enabled)
    retriever = BM25Retriever(load_runbooks(cfg["paths"]["runbooks"]))
    cluster = FixtureCluster(scenario) if scenario is not None else KubectlCluster(kube_context)
    tools = ToolRegistry(cluster=cluster, retriever=retriever, guards=guards)
    return Orchestrator(
        router or build_router(cfg), tools, guards,
        budget=budget_from(cfg), max_tool_steps=cfg.get("agents", {}).get("max_tool_steps", 8),
    )


def scenarios(cfg: dict) -> dict[str, dict]:
    return load_scenarios(cfg["paths"]["scenarios"])


def default_incident(s: dict) -> str:
    return f"Alerte : {s['description']} — namespace {s['namespace']}, environnement {s['environment']}."
