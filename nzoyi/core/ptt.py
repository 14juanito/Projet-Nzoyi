"""Pentest Tree (PTT) — shared context for all agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class PTTNode:
    """Single discovery or action recorded in the pentest tree."""

    node_id: str
    agent: str
    kind: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class PentestTree:
    """Central shared memory structure used by all NZOYI agents."""

    def __init__(self, target: str) -> None:
        self.target = target
        self._nodes: list[PTTNode] = []
        self._seen: set[str] = set()

    def add(self, agent: str, kind: str, data: dict[str, Any] | None = None) -> PTTNode:
        key = f"{agent}:{kind}:{sorted((data or {}).items())}"
        if key in self._seen:
            raise ValueError(f"Duplicate PTT entry: {kind} from {agent}")

        node = PTTNode(
            node_id=f"ptt-{len(self._nodes) + 1:04d}",
            agent=agent,
            kind=kind,
            data=data or {},
        )
        self._nodes.append(node)
        self._seen.add(key)
        return node

    def find(self, kind: str | None = None, agent: str | None = None) -> list[PTTNode]:
        results = self._nodes
        if kind is not None:
            results = [n for n in results if n.kind == kind]
        if agent is not None:
            results = [n for n in results if n.agent == agent]
        return results

    def summary(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "node_count": len(self._nodes),
            "agents": sorted({n.agent for n in self._nodes}),
            "kinds": sorted({n.kind for n in self._nodes}),
        }
