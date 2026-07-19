"""Client HTTP pour le détecteur Random Forest (service IDS-ML distant)."""

from __future__ import annotations

import logging
from typing import Any

import requests

logger = logging.getLogger("nzoyi.tools.rf_client")


class RFClient:
    """Interroge un service Flask exposant un modèle Random Forest via REST."""

    def __init__(self, endpoint: str, timeout: float = 3.0) -> None:
        self.endpoint = endpoint
        self.timeout = timeout

    def predict(self, features: dict[str, Any] | list[float]) -> dict[str, Any] | None:
        """Envoie le vecteur de features au service RF et renvoie sa prédiction.

        Args:
            features: Vecteur de features, sous forme de dict nommé ou de
                liste ordonnée, selon le contrat attendu par le service.

        Returns:
            ``{"label": int, "proba": float}`` ou ``None`` si le service est
            injoignable, indisponible ou renvoie une réponse invalide. Aucune
            valeur n'est fabriquée dans ce cas : l'appelant doit traiter
            ``None`` comme un signal neutre.
        """
        try:
            response = requests.post(self.endpoint, json=features, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return {"label": int(data["label"]), "proba": float(data["proba"])}
        except (requests.RequestException, KeyError, ValueError, TypeError) as exc:
            logger.warning("Endpoint RF injoignable (%s): %s", self.endpoint, exc)
            return None
