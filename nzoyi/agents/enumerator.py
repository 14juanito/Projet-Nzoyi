"""Enumeration agent — service fingerprinting."""

from __future__ import annotations

from typing import Any

from nzoyi.agents.base import BaseAgent


class EnumeratorAgent(BaseAgent):
    name = "enumerator"

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        services = {
            22: {"name": "ssh", "version": "OpenSSH 8.9"},
            80: {"name": "http", "version": "Apache 2.4.52"},
            21: {"name": "ftp", "version": "vsftpd 3.0.5"},
        }
        service_list = [
            {"port": port, **info} for port, info in services.items()
        ]
        result = {"services": services, "service_list": service_list, "dry_run": dry_run}
        self.ptt.set_enumeration_results(service_list)
        self.ptt.add(self.name, "service_enum", result)
        return result
