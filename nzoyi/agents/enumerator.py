"""Agent d'énumération — fingerprinting des services par banner grabbing TCP."""

from __future__ import annotations

import logging
import socket
from typing import Any

from nzoyi.agents.base import BaseAgent

logger = logging.getLogger("nzoyi.agents.enumerator")

BANNER_TIMEOUT = 2.0
BANNER_READ_SIZE = 256


class EnumeratorAgent(BaseAgent):
    """Affine les services des ports ouverts trouvés par Recon (PTT)."""

    name = "enumerator"

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        open_ports = self.ptt.get_recon_results()

        service_list: list[dict[str, Any]] = []
        for entry in open_ports:
            host = entry.get("host", self.ptt.target)
            port = entry["port"]
            banner = self._grab_banner(host, port)

            service_name = entry.get("service") or "unknown"
            product = entry.get("product", "")
            version = entry.get("version", "")
            if banner and not product and not version:
                product = banner

            service_list.append(
                {
                    "port": port,
                    "name": service_name,
                    "product": product,
                    "version": version,
                    "banner": banner,
                }
            )

        result = {
            "service_list": service_list,
            "services": {s["port"]: s for s in service_list},
            "dry_run": dry_run,
        }
        self.ptt.set_enumeration_results(service_list)
        self.ptt.add(self.name, "service_enum", result)
        return result

    @staticmethod
    def _grab_banner(host: str, port: int) -> str:
        """Tente une connexion TCP brute pour récupérer une bannière de service."""
        try:
            with socket.create_connection((host, port), timeout=BANNER_TIMEOUT) as sock:
                sock.settimeout(BANNER_TIMEOUT)
                data = sock.recv(BANNER_READ_SIZE)
                return data.decode(errors="ignore").strip()
        except OSError as exc:
            logger.debug("Banner grab échoué sur %s:%s (%s)", host, port, exc)
            return ""
