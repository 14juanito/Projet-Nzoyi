"""Backend générique pour toute API compatible OpenAI Chat Completions.

Volontairement l'inverse d'un adaptateur "OpenAI" dédié : un seul
:class:`OpenAICompatibleBackend`, paramétré par ``base_url``, sert n'importe
quel fournisseur qui expose l'API Chat Completions — OpenRouter aujourd'hui
(pas encore de facturation GPT-6 Astra native), GPT-6 Astra lui-même demain, et
des modèles locaux via Ollama en J3/J4. Changer de fournisseur ne touche jamais
ce fichier : seules les valeurs de configuration (``base_url``/``model``/clé)
changent.

Comme :class:`~nzoyi.llm.backends.anthropic_backend.AnthropicBackend`, ce
backend implémente strictement le contrat :class:`~nzoyi.llm.backend.LLMBackend`
— aucun parsing/validation JSON ici, cette responsabilité reste entièrement
dans :meth:`LLMOrchestrator._sanitize`.

Gestion des secrets dans les erreurs : même discipline qu'`AnthropicBackend`.
Aucune exception levée par le SDK ``openai`` n'est jamais interpolée dans le
message de :class:`LLMBackendError` propagé — le détail complet part
uniquement dans les logs serveur (``logger.error(..., exc_info=True)``) ; le
message propagé (et donc tout ce qui finit dans le PTT) reste un texte
générique fixe. Voir :meth:`OpenAICompatibleBackend.decide`.
"""

from __future__ import annotations

import logging
from typing import Any

from nzoyi.llm.backend import LLMBackend, LLMBackendError

try:  # openai est optionnel : les runs hors-ligne retombent sur le fallback.
    import openai
except ImportError:  # pragma: no cover - garde de dépendance
    openai = None  # type: ignore[assignment]

logger = logging.getLogger("nzoyi.llm.backends.openai_compat")


class OpenAICompatibleBackend(LLMBackend):
    """Adaptateur :class:`LLMBackend` pour toute API Chat Completions compatible OpenAI.

    Sert OpenRouter (``base_url="https://openrouter.ai/api/v1"``) aujourd'hui,
    GPT-6 Astra demain, et des modèles locaux via Ollama en J3/J4 — en ne
    changeant que ``base_url``/``model``/clé, jamais le code.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None,
        temperature: float | None = 0.0,
        reasoning_effort: str | None = None,
        max_tokens: int = 1024,
    ) -> None:
        """Construit le backend et le client ``openai`` sous-jacent.

        Args:
            base_url: URL de base de l'API compatible (ex. OpenRouter, Astra, Ollama).
            model: Identifiant du modèle chez ce fournisseur.
            api_key: Clé API, ou ``None`` si absente.
            temperature: Température d'échantillonnage, ou ``None`` pour ne pas
                l'envoyer du tout. Optionnelle à dessein (contrainte 4) : un
                fournisseur donné ne supporte en général que l'un des deux
                paramètres de contrôle du raisonnement — ``temperature``
                (OpenRouter/DeepSeek-R1, défaut ``0.0`` ici pour rester
                cohérent avec l'exigence de reproductibilité du framework) ou
                ``reasoning_effort`` (GPT-6 Astra, pressenti). La bascule entre
                les deux se fait entièrement par configuration (quel argument
                est ``None`` à la construction), jamais par une branche de
                code sur l'identité du fournisseur.
            reasoning_effort: Niveau d'effort de raisonnement, ou ``None`` pour
                ne pas l'envoyer. Voir ``temperature`` ci-dessus.
            max_tokens: Plafond de tokens en sortie (identique à l'historique : 1024).

        Raises:
            LLMBackendError: Si la dépendance ``openai`` n'est pas installée,
                ou si la construction du client échoue. Dans ce second cas, le
                message est un texte générique fixe — jamais l'exception
                d'origine du SDK, qui peut contenir la clé API sous une forme
                quelconque. Le détail complet est loggé en ``ERROR`` avec
                ``exc_info=True`` pour le diagnostic.
        """
        if openai is None:
            raise LLMBackendError(
                "Dépendance 'openai' absente — backend OpenAI-compatible indisponible."
            )

        self.base_url = base_url
        self.model = model
        self.temperature = temperature
        self.reasoning_effort = reasoning_effort
        self.max_tokens = max_tokens

        try:
            self._client: Any = openai.OpenAI(base_url=base_url, api_key=api_key)
        except Exception:
            logger.error("Construction du client OpenAI-compatible échouée", exc_info=True)
            raise LLMBackendError("Échec de l'initialisation du backend OpenAI-compatible") from None

    def decide(self, system_prompt: str, user_message: str) -> str:
        """Interroge le fournisseur et renvoie le texte brut de la réponse (sans parsing).

        Args:
            system_prompt: Instruction système (message de rôle ``system``).
            user_message: Message utilisateur (résumé sérialisé du PTT).

        Returns:
            Le contenu brut du premier choix (``response.choices[0].message.content``).

        Raises:
            LLMBackendError: Sur toute défaillance de l'appel (réseau, API, …).
                Le message propagé est un texte générique fixe — l'exception
                d'origine (``str(exc)``, ``exc.args``, ``exc.response``, etc.)
                n'est **jamais** interpolée dedans, car le SDK peut y exposer la
                clé API sous un format imprévisible. Le détail complet de
                l'exception d'origine est loggé côté serveur via
                ``logger.error(..., exc_info=True)`` — jamais dans l'exception
                propagée ni, par extension, dans le PTT.
        """
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        }
        # N'ajoute temperature/reasoning_effort que si explicitement fournis
        # (contrainte 4) : ne jamais forcer les deux à la fois, un fournisseur
        # donné ne supportant en général que l'un des deux.
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if self.reasoning_effort is not None:
            kwargs["reasoning_effort"] = self.reasoning_effort

        try:
            response = self._client.chat.completions.create(**kwargs)
            return response.choices[0].message.content or ""
        except Exception:
            logger.error("Appel OpenAI-compatible échoué", exc_info=True)
            raise LLMBackendError("Échec de l'appel au backend OpenAI-compatible") from None
