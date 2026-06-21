"""Pentest Tree (PTT) — shared context for all agents."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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
        self._lock = threading.RLock()
        self._nodes: list[PTTNode] = []
        self._seen: set[str] = set()
        self._recon_results: list[dict[str, Any]] = []
        self._enumeration_results: list[dict[str, Any]] = []
        self._vulnerabilities: list[dict[str, Any]] = []
        self._attack_attempts: list[dict[str, Any]] = []
        self._evasion_strategy: dict[str, Any] = {}
        self._evaluations: list[dict[str, Any]] = []

    def add(
        self,
        agent: str,
        kind: str,
        data: dict[str, Any] | None = None,
        *,
        allow_duplicate: bool = False,
    ) -> PTTNode:
        payload = data or {}
        key = f"{agent}:{kind}:{sorted(payload.items())}"
        with self._lock:
            if not allow_duplicate and key in self._seen:
                raise ValueError(f"Duplicate PTT entry: {kind} from {agent}")

            node = PTTNode(
                node_id=f"ptt-{len(self._nodes) + 1:04d}",
                agent=agent,
                kind=kind,
                data=payload,
            )
            self._nodes.append(node)
            if not allow_duplicate:
                self._seen.add(key)
            return node

    def find(self, kind: str | None = None, agent: str | None = None) -> list[PTTNode]:
        with self._lock:
            results = list(self._nodes)
        if kind is not None:
            results = [n for n in results if n.kind == kind]
        if agent is not None:
            results = [n for n in results if n.agent == agent]
        return results

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "target": self.target,
                "node_count": len(self._nodes),
                "agents": sorted({n.agent for n in self._nodes}),
                "kinds": sorted({n.kind for n in self._nodes}),
                "detection_rate": self.get_detection_rate(),
            }

    # ── Structured write methods ───────────────────────────────────────────

    def set_recon_results(self, ports: list[dict[str, Any]]) -> None:
        with self._lock:
            self._recon_results = list(ports)

    def set_enumeration_results(self, services: list[dict[str, Any]]) -> None:
        with self._lock:
            self._enumeration_results = list(services)

    def add_vulnerability(self, vuln: dict[str, Any]) -> None:
        with self._lock:
            self._vulnerabilities.append(dict(vuln))

    def record_attack_attempt(self, attempt: dict[str, Any]) -> None:
        with self._lock:
            self._attack_attempts.append(dict(attempt))

    def update_evasion_strategy(self, strategy: dict[str, Any]) -> None:
        with self._lock:
            self._evasion_strategy = dict(strategy)

    def record_evaluation(
        self, detected: bool, alert_details: dict[str, Any] | None = None
    ) -> None:
        entry = {"detected": detected, "alert_details": alert_details or {}}
        with self._lock:
            self._evaluations.append(entry)

    # ── Structured read methods ──────────────────────────────────────────────

    def get_recon_results(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._recon_results)

    def get_vulnerabilities(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._vulnerabilities)

    def get_detection_rate(self) -> float:
        with self._lock:
            if not self._evaluations:
                return 0.0
            detected = sum(1 for e in self._evaluations if e["detected"])
            return detected / len(self._evaluations)

    def get_evasion_strategy(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._evasion_strategy)

    # ── Serialization ──────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "target": self.target,
                "nodes": [asdict(n) for n in self._nodes],
                "recon_results": self._recon_results,
                "enumeration_results": self._enumeration_results,
                "vulnerabilities": self._vulnerabilities,
                "attack_attempts": self._attack_attempts,
                "evasion_strategy": self._evasion_strategy,
                "evaluations": self._evaluations,
            }

    def save(self, path: str | Path) -> None:
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, default=str)

    @classmethod
    def load(cls, path: str | Path) -> PentestTree:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        ptt = cls(data["target"])
        with ptt._lock:
            ptt._recon_results = data.get("recon_results", [])
            ptt._enumeration_results = data.get("enumeration_results", [])
            ptt._vulnerabilities = data.get("vulnerabilities", [])
            ptt._attack_attempts = data.get("attack_attempts", [])
            ptt._evasion_strategy = data.get("evasion_strategy", {})
            ptt._evaluations = data.get("evaluations", [])
            for node_data in data.get("nodes", []):
                node = PTTNode(**node_data)
                ptt._nodes.append(node)
        return ptt
