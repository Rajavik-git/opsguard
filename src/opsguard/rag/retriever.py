"""Runbook RAG: section-aware chunking + BM25 retrieval (dependency-free).

Chunks keep their runbook id and section so that every recommendation can be
cited (`[RB-001#remediation]`) and checked by the grounding guardrail.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = {"le", "la", "les", "de", "des", "du", "un", "une", "et", "en", "a", "the", "is", "of", "to", "in", "sur", "pour", "est", "par", "dans", "ou"}


def _norm(text: str) -> list[str]:
    text = unicodedata.normalize("NFKD", text.lower()).encode("ascii", "ignore").decode()
    return [t for t in _TOKEN.findall(text) if t not in _STOP]


@dataclass
class Chunk:
    id: str
    runbook_id: str
    title: str
    section: str
    text: str
    tags: list[str] = field(default_factory=list)

    @property
    def citation(self) -> str:
        return f"[{self.id}]"


def _slug(s: str) -> str:
    s = unicodedata.normalize("NFKD", s.lower()).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", s).strip("-")


def load_runbooks(directory: str | Path) -> list[Chunk]:
    chunks: list[Chunk] = []
    for path in sorted(Path(directory).glob("*.md")):
        raw = path.read_text(encoding="utf-8")
        meta: dict[str, str] = {}
        body = raw
        if raw.startswith("---"):
            _, fm, body = raw.split("---", 2)
            for line in fm.strip().splitlines():
                k, _, v = line.partition(":")
                meta[k.strip()] = v.strip()
        rb_id = meta.get("id", path.stem)
        title = meta.get("title", path.stem)
        tags = [t.strip() for t in meta.get("tags", "").strip("[]").split(",") if t.strip()]
        for part in re.split(r"(?m)^## ", body):
            part = part.strip()
            if not part:
                continue
            section, _, text = part.partition("\n")
            chunks.append(Chunk(f"{rb_id}#{_slug(section)}", rb_id, title, section.strip(), text.strip(), tags))
    return chunks


class BM25Retriever:
    def __init__(self, chunks: list[Chunk], k1: float = 1.5, b: float = 0.75):
        self.chunks, self.k1, self.b = chunks, k1, b
        # title and tags are indexed with the body (cheap field boosting)
        self._docs = [_norm(f"{c.title} {c.title} {' '.join(c.tags)} {c.section} {c.text}") for c in chunks]
        self._tf = [Counter(d) for d in self._docs]
        self._avgdl = sum(map(len, self._docs)) / max(1, len(self._docs))
        df: Counter = Counter()
        for d in self._docs:
            df.update(set(d))
        n = len(self._docs)
        self._idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def search(self, query: str, k: int = 3) -> list[tuple[Chunk, float]]:
        q = _norm(query)
        scores = []
        for i, tf in enumerate(self._tf):
            dl = len(self._docs[i])
            s = 0.0
            for t in q:
                if t not in tf:
                    continue
                f = tf[t]
                s += self._idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * dl / self._avgdl))
            if s > 0:
                scores.append((self.chunks[i], s))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:k]

    def get(self, chunk_id: str) -> Chunk | None:
        return next((c for c in self.chunks if c.id == chunk_id), None)
