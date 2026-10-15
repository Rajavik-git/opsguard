"""Context engineering: what goes into each LLM call, in what order, within which budget.

- Section budgets (case file, evidence, runbooks) instead of "dump everything".
- Evidence digest: only signal lines (errors, warnings, probe/OOM/pull failures) from tool outputs.
- History compaction for the tool loop: old tool results are replaced by their digest
  once the conversation exceeds the budget, keeping the most recent turns verbatim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from ..llm.tokens import count_messages, count_tokens, truncate_to_tokens
from ..llm.types import Message

SIGNAL = re.compile(
    r"(?i)\b(error|fatal|warn(ing)?|failed|refused|oomkill\w*|back-?off|unhealthy|crashloop\w*|errimagepull|exit code|quarantined|not found)\b"
)


def evidence_digest(text: str, max_lines: int = 25) -> str:
    lines = [ln.strip() for ln in text.splitlines() if SIGNAL.search(ln)]
    seen, out = set(), []
    for ln in lines:  # de-duplicate repeated log lines (crash loops are very repetitive)
        key = re.sub(r"\d", "#", ln)
        if key not in seen:
            seen.add(key)
            out.append(ln[:240])
    return "\n".join(out[:max_lines])


@dataclass
class ContextBudget:
    total: int = 6000
    evidence: int = 1500
    runbooks: int = 1500
    keep_last_turns: int = 4


def compact_history(messages: list[Message], budget: ContextBudget) -> list[Message]:
    """Keep system + task + last N messages verbatim; digest older tool outputs."""
    if count_messages(messages) <= budget.total:
        return messages
    head, body = messages[:2], messages[2:]
    cut = max(0, len(body) - budget.keep_last_turns)
    compacted = [
        replace(m, content=f"[compacted] {evidence_digest(m.content, 8) or '(no signal)'}") if m.role == "tool" else m
        for m in body[:cut]
    ]
    return head + compacted + body[cut:]


def build_remediation_context(findings_json: str, tool_outputs: list[str], runbook_text: str, budget: ContextBudget) -> str:
    digest = truncate_to_tokens(evidence_digest("\n".join(tool_outputs)), budget.evidence)
    runbooks = truncate_to_tokens(runbook_text, budget.runbooks)
    return (
        f"<findings>\n{findings_json}\n</findings>\n\n"
        f"<evidence_digest>\n{digest}\n</evidence_digest>\n\n"
        f"<runbooks>\n{runbooks}\n</runbooks>"
    )


def token_report(sections: dict[str, str]) -> dict[str, int]:
    return {k: count_tokens(v) for k, v in sections.items()}
