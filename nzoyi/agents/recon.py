"""Reconnaissance agent — network discovery."""

from __future__ import annotations

from typing import Any

from nzoyi.agents.base import BaseAgent


class ReconAgent(BaseAgent):
    name = "recon"

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        ports = [22, 80, 443, 21]
        result = {
            "target": self.ptt.target,
            "open_ports": ports,
            "timing": self.profile.nmap_timing,
            "dry_run": dry_run,
        }
        self.ptt.add(self.name, "port_scan", result)
        return result
