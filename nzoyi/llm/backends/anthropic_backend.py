"""Backend Anthropic (Claude) pour la couche LLM stratégique.

Ce module encapsule derrière l'interface :class:`~nzoyi.llm.backend.LLMBackend`
la logique d'appel qui était jusqu'ici inline dans ``LLMOrchestrator.decide`` :
construction du client Anthropic, appel à ``messages.create`` et extraction du
texte depuis ``response.content``.

Le module reste importable même sans la dépendance ``anthropic`` installée (les
exécutions hors-ligne retombent sur le repli déterministe de l'Orchestrator) :
on reproduit la garde d'import ``try/except ImportError`` historique, et on ne
lève :class:`LLMBackendError` qu'à l'*instanciation* si la dépendance manque —
jamais à l'import du module.

Gestion des secrets dans les erreurs : aucune exception levée par le SDK
Anthropic n'est jamais interpolée dans le message de :class:`LLMBackendError`
propagé à l'appelant — qu'elle contienne la clé API en entier, tronquée, ou
sous toute autre forme que le SDK choisirait. Le détail complet part
uniquement dans les logs serveur (``logger.error(..., exc_info=True)``) ; le
message propagé (et donc tout ce qui finit dans le PTT) reste un texte
générique fixe. Voir :meth:`AnthropicBackend.decide`.
"""

from __future__ import annotations

import logging
from typing import Any

from nzoyi.llm.backend import LLMBackend, LLMBackendError

try:  # anthropic est optionnel : les runs hors-ligne retombent sur le fallback.
    import anthropic
except ImportError:  # pragma: no cover - garde de dépendance
    anthropic = None  # type: ignore[assignment]

logger = logging.getLogger("nzoyi.llm.backends.anthropic")


class AnthropicBackend(LLMBackend):
    """Adaptateur :class:`LLMBackend` s'appuyant sur le SDK Anthropic (Claude)."""

    def __init__(
        self,
        model: str,
        temperature: float,
        api_key: str | None,
        max_tokens: int = 1024,
    ) -> None:
        """Construit le backend et le client Anthropic sous-jacent.

        Args:
            model: Identifiant du modèle Anthropic.
            temperature: Température d'échantillonnage (0.0 = stratégie déterministe).
            api_key: Clé API Anthropic, ou ``None`` si absente.
            max_tokens: Plafond de tokens en sortie (identique à l'historique : 1024).

        Raises:
            LLMBackendError: Si la dépendance ``anthropic`` n'est pas installée,
                ou si la construction du client échoue. Dans ce second cas, le
                message est un texte générique fixe — jamais l'exception
                d'origine du SDK, qui peut contenir la clé API sous une forme
                quelconque. Le détail complet est loggé en ``ERROR`` avec
                ``exc_info=True`` pour le diagnostic.
        """
        if anthropic is None:
            raise LLMBackendError(
                "Dépendance 'anthropic' absente — backend Anthropic indisponible."
            )

        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

        try:
            self._client: Any = anthropic.Anthropic(api_key=api_key)
        except Exception:
            logger.error("Construction du client Anthropic échouée", exc_info=True)
            raise LLMBackendError("Échec de l'initialisation du backend Anthropic") from None

    def decide(self, system_prompt: str, user_message: str) -> str:
        """Interroge Claude et renvoie le texte brut de la réponse (sans parsing).

        Reproduit exactement l'appel historique de ``LLMOrchestrator.decide`` :
        ``messages.create`` avec le même ``max_tokens`` et la même extraction des
        blocs de type ``text`` depuis ``response.content``.

        Args:
            system_prompt: Instruction système passée au paramètre ``system``.
            user_message: Message utilisateur (résumé sérialisé du PTT).

        Returns:
            La concaténation du texte des blocs ``text`` de la réponse.

        Raises:
            LLMBackendError: Sur toute défaillance de l'appel (réseau, API, …).
                Le message propagé est un texte générique fixe — l'exception
                d'origine (``str(exc)``, ``exc.args``, ``exc.response``, etc.)
                n'est **jamais** interpolée dedans, car le SDK peut y exposer la
                clé API sous un format imprévisible (entière, tronquée,
                ré-encodée, dans un en-tête de requête…) qu'aucun scrubbing par
                remplacement littéral ne peut garantir de couvrir. Le détail
                complet de l'exception d'origine est loggé côté serveur via
                ``logger.error(..., exc_info=True)`` — jamais dans l'exception
                propagée ni, par extension, dans le PTT — pour rester
                diagnosticable sans jamais pouvoir fuiter un secret.
        """
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_message}],
            )
            return "".join(
                block.text
                for block in response.content
                if getattr(block, "type", None) == "text"
            )
        except Exception:
            logger.error("Appel Anthropic échoué", exc_info=True)
            raise LLMBackendError("Échec de l'appel au backend Anthropic") from None
