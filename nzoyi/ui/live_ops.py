"""Live Ops NZOYI — tableau des cycles en temps réel (sortie texte simple)."""

from __future__ import annotations

import sys
from typing import Any


class LiveOpsConsole:
    """Affiche Cycle / Détecté / Reward / ε / Détection % au fil de l'eau.

    Pas de Rich Live plein écran : une ligne par cycle (fiable dans n'importe
    quel terminal, y compris avec les logs agents en parallèle).
    """

    def __init__(
        self,
        target: str,
        profile: str,
        eve_log: str | None = None,
        cycles_total: int | None = None,
        attacker_ip: str = "192.168.100.10",
    ) -> None:
        self.target = target
        self.profile = profile
        self.eve_log = eve_log
        self.cycles_total = cycles_total
        self.attacker_ip = attacker_ip
        self.enabled = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

        self.phase = "init"
        self.ports: list[int] = []
        self.vulns = 0
        self._rows: list[dict[str, Any]] = []
        self._header_printed = False

    def start(self) -> None:
        if not self.enabled:
            return
        self.phase = "préparation"
        total = self.cycles_total or "?"
        print(
            f"  {self.attacker_ip} → {self.target}  ·  {self.profile}  ·  {total} cycles"
        )
        print(f"  {'─' * 55}")
        print(f"  {'Cycle':<8} {'Détecté':<10} {'Reward':<10} {'ε':<10} {'Détection %':<12}")
        print(f"  {'─' * 55}")
        self._header_printed = True
        sys.stdout.flush()

    def stop(self) -> None:
        if self.enabled and self._header_printed:
            print(f"  {'─' * 55}")
            sys.stdout.flush()
        self.phase = "terminé"

    def push_agent_event(self, agent: str, detail: str = "") -> None:
        self.phase = f"{agent}" + (f" · {detail}" if detail else "")

    def update_cycle(
        self,
        *,
        cycle: int,
        action: str | None = None,
        epsilon: float | None = None,
        detection_rate: float | None = None,
        rf_proba: float | None = None,
        alert_count: int | None = None,
        detected: bool | None = None,
        reward: float | None = None,
        ports: list[int] | None = None,
        vulns: int | None = None,
        suricata_detected: bool | None = None,
    ) -> None:
        if ports is not None:
            self.ports = ports
        if vulns is not None:
            self.vulns = vulns

        if cycle < 1 or detected is None:
            return

        row = {
            "cycle": cycle,
            "detected": bool(detected),
            "reward": float(reward or 0.0),
            "epsilon": float(epsilon or 0.0),
            "detection_rate": float(detection_rate or 0.0),
            "action": action or "—",
            "rf_proba": float(rf_proba or 0.0),
            "alerts": int(alert_count or 0),
            "suricata": bool(suricata_detected)
            if suricata_detected is not None
            else int(alert_count or 0) > 0,
        }
        if self._rows and self._rows[-1]["cycle"] == cycle:
            self._rows[-1] = row
        else:
            self._rows.append(row)

        if self.enabled:
            det = "OUI" if row["detected"] else "NON"
            rew = row["reward"]
            rew_s = f"+{rew:.1f}" if rew > 0 else f"{rew:.1f}"
            print(
                f"  {row['cycle']:<8} {det:<10} {rew_s:<10} "
                f"{row['epsilon']:<10.4f} {row['detection_rate']:<12.1%}"
            )
            sys.stdout.flush()
