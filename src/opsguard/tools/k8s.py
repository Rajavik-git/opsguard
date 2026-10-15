"""Read-only Kubernetes tools exposed to agents (and to MCP clients).

Two backends share the same interface:
- `FixtureCluster`: deterministic scenarios (tests, demo, red team) — no cluster needed.
- `KubectlCluster`: real cluster through `kubectl`, restricted to read-only verbs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Protocol

from ..llm.types import ToolSpec


class ClusterBackend(Protocol):
    def list_pods(self, namespace: str) -> str: ...
    def get_events(self, namespace: str) -> str: ...
    def get_pod_logs(self, namespace: str, pod: str, tail: int = 50) -> str: ...
    def describe_deployment(self, namespace: str, name: str) -> str: ...


class FixtureCluster:
    def __init__(self, scenario: dict):
        self.s = scenario

    def _check_ns(self, namespace: str) -> str | None:
        if namespace != self.s["namespace"]:
            return f"No resources found in {namespace} namespace."
        return None

    def list_pods(self, namespace: str) -> str:
        if err := self._check_ns(namespace):
            return err
        rows = ["NAME                          READY  STATUS             RESTARTS  NODE"]
        for p in self.s["pods"]:
            line = f"{p['name']:<29} {p['ready']:<6} {p['status']:<18} {p['restarts']:<9} {p['node']}"
            if p.get("last_termination"):
                line += f"   lastState: {p['last_termination']}"
            rows.append(line)
        return "\n".join(rows)

    def get_events(self, namespace: str) -> str:
        return self._check_ns(namespace) or "\n".join(self.s["events"])

    def get_pod_logs(self, namespace: str, pod: str, tail: int = 50) -> str:
        if err := self._check_ns(namespace):
            return err
        logs = self.s["logs"].get(pod)
        if logs is None:
            return f'Error from server (NotFound): pods "{pod}" not found'
        return "\n".join(logs.splitlines()[-tail:]) or "(no logs: container never started)"

    def describe_deployment(self, namespace: str, name: str) -> str:
        if err := self._check_ns(namespace):
            return err
        d = self.s["deployments"].get(name)
        if d is None:
            return f'Error from server (NotFound): deployments.apps "{name}" not found'
        return json.dumps({"name": name, **d}, indent=2, ensure_ascii=False)


class KubectlCluster:
    """Real cluster access. Only read-only verbs are ever constructed here."""

    def __init__(self, context: str | None = None):
        if not shutil.which("kubectl"):
            raise RuntimeError("kubectl not found in PATH")
        self.base = ["kubectl"] + (["--context", context] if context else [])

    def _run(self, *args: str) -> str:
        r = subprocess.run([*self.base, *args], capture_output=True, text=True, timeout=20)
        return (r.stdout or r.stderr).strip()

    def list_pods(self, namespace):
        return self._run("get", "pods", "-n", namespace, "-o", "wide")

    def get_events(self, namespace):
        return self._run("get", "events", "-n", namespace, "--sort-by=.lastTimestamp")

    def get_pod_logs(self, namespace, pod, tail=50):
        return self._run("logs", pod, "-n", namespace, f"--tail={int(tail)}", "--previous=false")

    def describe_deployment(self, namespace, name):
        return self._run("describe", "deployment", name, "-n", namespace)


_NS = {"type": "string", "description": "Kubernetes namespace"}

TOOL_SPECS: list[ToolSpec] = [
    ToolSpec("list_pods", "List pods of a namespace with status and restarts.",
             {"type": "object", "properties": {"namespace": _NS}, "required": ["namespace"]}),
    ToolSpec("get_events", "Recent Kubernetes events of a namespace.",
             {"type": "object", "properties": {"namespace": _NS}, "required": ["namespace"]}),
    ToolSpec("get_pod_logs", "Last log lines of a pod.",
             {"type": "object", "properties": {"namespace": _NS, "pod": {"type": "string"}, "tail": {"type": "integer", "default": 50}},
              "required": ["namespace", "pod"]}),
    ToolSpec("describe_deployment", "Deployment spec: image, env, resources, probes.",
             {"type": "object", "properties": {"namespace": _NS, "name": {"type": "string"}}, "required": ["namespace", "name"]}),
    ToolSpec("search_runbooks", "Search the internal SRE runbooks (RAG). Returns cited sections.",
             {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
]


def load_scenarios(path: str | Path) -> dict[str, dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
