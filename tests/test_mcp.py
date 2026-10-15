import asyncio
import json
import os

import pytest

pytest.importorskip("mcp")


def _text(result) -> str:
    content = result.content if hasattr(result, "content") else result[0] if isinstance(result, tuple) else result
    return content[0].text


def test_mcp_server_tools(monkeypatch):
    monkeypatch.setenv("OPSGUARD_SCENARIO", "payments-crashloop")
    import importlib

    import opsguard.mcp_server as srv

    importlib.reload(srv)

    async def go():
        names = {t.name for t in await srv.mcp.list_tools()}
        assert {"list_pods", "search_runbooks", "check_command", "investigate_incident"} <= names
        verdict = json.loads(_text(await srv.mcp.call_tool("check_command", {"command": "kubectl delete ns payments"})))
        assert verdict["decision"] == "block"
        denied = _text(await srv.mcp.call_tool("list_pods", {"namespace": "kube-system"}))
        assert "access denied" in denied
        pods = _text(await srv.mcp.call_tool("list_pods", {"namespace": "payments"}))
        assert "CrashLoopBackOff" in pods

    asyncio.run(go())
    os.environ.pop("OPSGUARD_SCENARIO", None)
