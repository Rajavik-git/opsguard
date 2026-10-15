"""Command-line interface.

  opsguard scenarios                         list demo scenarios
  opsguard investigate -s payments-crashloop investigate an incident
  opsguard check "kubectl delete ns prod"    classify a command against the policy
  opsguard redteam --fail-above 0.0          red-team suite (CI security gate)
  opsguard mcp                               start the MCP server (stdio)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .guardrails import Guardrails
from .llm import LLMRouter, MockSREProvider
from .runtime import build_orchestrator, default_incident, load_config, scenarios


def _cmd_scenarios(cfg, _args):
    for name, s in scenarios(cfg).items():
        print(f"{name:<22} {s['namespace']:<10} {s['environment']:<8} {s['description']}")


def _cmd_investigate(cfg, args):
    scenario = scenarios(cfg)[args.scenario] if args.scenario else None
    if scenario is None and not args.incident:
        sys.exit("error: give --scenario or an incident text (real cluster mode)")
    router = LLMRouter([MockSREProvider(latency_ms=args.mock_latency)]) if args.mock else None
    orch = build_orchestrator(cfg, scenario, guardrails_enabled=not args.no_guardrails, router=router,
                              kube_context=args.kube_context)
    report = orch.run(args.incident or default_incident(scenario))
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=str) if args.json else report.to_markdown())
    return 0 if report.status != "error" else 1


def _cmd_check(cfg, args):
    v = Guardrails(cfg["paths"]["policy"]).classify_command(args.command)
    print(f"{v.decision.value:<17} {v.rule:<22} {v.reason}")
    return 0 if v.decision.value != "block" else 2


def _cmd_redteam(cfg, args):
    from .harness import RedTeamHarness, to_markdown

    results = RedTeamHarness(cfg, provider=args.provider, workers=args.workers, latency_ms=args.mock_latency).run()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "redteam_results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    md = to_markdown(results)
    (out / "redteam_report.md").write_text(md, encoding="utf-8")
    print(md)
    asr = results["summary"]["asr_with_guardrails"]
    if args.fail_above is not None and asr > args.fail_above:
        print(f"SECURITY GATE FAILED: ASR with guardrails {asr:.0%} > {args.fail_above:.0%}", file=sys.stderr)
        return 1
    return 0


def _cmd_mcp(_cfg, args):
    if args.scenario:
        os.environ["OPSGUARD_SCENARIO"] = args.scenario
    from .mcp_server import main

    main()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="opsguard", description="Secure agentic SRE copilot for Kubernetes/OpenShift")
    p.add_argument("--config", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scenarios")

    inv = sub.add_parser("investigate")
    inv.add_argument("incident", nargs="?", default=None)
    inv.add_argument("-s", "--scenario")
    inv.add_argument("--mock", action="store_true", help="force the offline model")
    inv.add_argument("--mock-latency", type=float, default=0.0)
    inv.add_argument("--no-guardrails", action="store_true")
    inv.add_argument("--kube-context")
    inv.add_argument("--json", action="store_true")

    chk = sub.add_parser("check")
    chk.add_argument("command")

    rt = sub.add_parser("redteam")
    rt.add_argument("--provider", default="mock", choices=["mock", "config"])
    rt.add_argument("--workers", type=int, default=4)
    rt.add_argument("--mock-latency", type=float, default=0.0)
    rt.add_argument("--out", default="reports")
    rt.add_argument("--fail-above", type=float, default=None, help="CI gate on attack success rate")

    mc = sub.add_parser("mcp")
    mc.add_argument("-s", "--scenario")

    args = p.parse_args(argv)
    cfg = load_config(args.config)
    handler = {"scenarios": _cmd_scenarios, "investigate": _cmd_investigate, "check": _cmd_check,
               "redteam": _cmd_redteam, "mcp": _cmd_mcp}[args.cmd]
    return handler(cfg, args) or 0


if __name__ == "__main__":
    sys.exit(main())
