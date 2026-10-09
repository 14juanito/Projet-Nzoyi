"""Couche LLM de RATIONALE EXPLICATIF SEUL — lecture seule, zéro influence.

STRICT separation of concerns : ce composant génère un résumé en langage
naturel d'un résultat d'évaluation DÉJÀ CALCULÉ par la fusion déterministe
Suricata + RF (:meth:`~nzoyi.agents.evaluation.EvaluationAgent.run`). Il ne
reçoit ``result`` qu'en LECTURE, jamais les données brutes, et n'a ZÉRO
influence sur ``detected``/``detection_rate`` — ces champs restent calculés
exactement comme avant ; le LLM n'intervient qu'APRÈS, pour expliquer un
résultat déjà figé.

Même pattern que :class:`~nzoyi.llm.orchestrator_llm.LLMOrchestrator` (J1) :
backend injectable via :func:`~nzoyi.llm.backend_resolver.resolve_backend`,
repli déterministe systématique, ``last_raw_response`` exposé pour que
l'agent appelant (jamais cette classe) loggue dans le PTT.
"""

from __future__ import annotations

import json
import logging
import time

from nzoyi.llm.backend import LLMBackend
from nzoyi.llm.backend_resolver import resolve_backend

logger = logging.getLogger("nzoyi.llm.evaluation_rationale")

DEFAULT_MODEL = "claude-sonnet-5"
MAX_RATIONALE_LENGTH = 500

SYSTEM_PROMPT = (
    "Tu es la couche de RATIONALE EXPLICATIF d'un pentest de lab isolé "
    "(recherche académique autorisée). Tu reçois un résultat d'évaluation "
    "DÉJÀ CALCULÉ (fusion déterministe Suricata + RF) — tu ne dois JAMAIS le "
    "recalculer ni le remettre en question, seulement l'EXPLIQUER en langage "
    "naturel, de façon concise. Réponds UNIQUEMENT en JSON, sans texte, avec "
    'exactement ce schéma : {"rationale": str}.'
)


class EvaluationRationaleLLM:
    """Rationale explicatif LLM d'un résultat d'évaluation — lecture seule."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.0,
        enabled: bool = True,
        backend: LLMBackend | None = None,
    ) -> None:
        """Initialise la couche de rationale.

        Args:
            model: Identifiant de modèle Anthropic. Si ``None``, résolu via
                ``NZOYI_ANTHROPIC_MODEL`` puis :data:`DEFAULT_MODEL`.
            temperature: Température d'échantillonnage (0.0 = rationale déterministe).
            enabled: Quand ``False``, le LLM est contourné et aucun rationale
                n'est généré (chaîne vide).
            backend: Backend :class:`~nzoyi.llm.backend.LLMBackend` à injecter
                directement (tests, ou futur fournisseur). Prime sur
                ``NZOYI_LLM_PROVIDER``.
        """
        self.model = model or DEFAULT_MODEL
        self.temperature = temperature
        self.enabled = enabled
        self.last_raw_response: str | None = None
        #: Durée de l'appel réel au backend (``decide()`` seul), ou ``None``
        #: si aucun appel n'a été tenté (désactivé / backend indisponible).
        #: Alimente le comparatif J7 (latence par modèle du panel).
        self.last_latency_s: float | None = None
        #: ``None`` si le dernier appel a abouti au JSON attendu ; sinon un
        #: motif court et fixe (jamais le détail de l'exception — même
        #: discipline que les backends eux-mêmes) : alimente le taux de
        #: fallback par modèle du comparatif J7.
        self.last_fallback_reason: str | None = None
        self.backend: LLMBackend | None = None
        self.provider: str | None = None

        if self.enabled:
            resolved_backend, resolved_provider, resolved_model = resolve_backend(
                explicit_backend=backend,
                model_override=model,
                temperature=self.temperature,
                default_model=DEFAULT_MODEL,
                env_prefix="ANTHROPIC",
            )
            self.backend = resolved_backend
            self.provider = resolved_provider
            if resolved_provider == "openai_compatible":
                self.model = resolved_model

    def decide(self, result: dict) -> str:
        """Génère un rationale en langage naturel pour ``result`` (lecture seule).

        Args:
            result: Résultat d'évaluation DÉJÀ CALCULÉ (``detected``,
                ``detection_rate``, ``alert_count``, ``rf_proba``, …). Jamais
                modifié, jamais recalculé.

        Returns:
            Le rationale (chaîne, tronquée à :data:`MAX_RATIONALE_LENGTH`
            caractères). Chaîne vide si le LLM est désactivé/indisponible ou
            si l'appel échoue — ``result["detected"]``/``detection_rate``
            restent inchangés dans tous les cas (cette classe ne les touche
            jamais).
        """
        if not self.enabled or self.backend is None:
            reason = "LLM désactivé" if not self.enabled else "backend indisponible"
            logger.info("Rationale évaluation contourné (%s) — chaîne vide.", reason)
            self.last_fallback_reason = "disabled" if not self.enabled else "backend_unavailable"
            return ""

        user_message = json.dumps(result, ensure_ascii=False, default=str)
        logger.info("Rationale évaluation prompt (%s): %s", self.model, user_message)

        t0 = time.perf_counter()
        try:
            text = self.backend.decide(SYSTEM_PROMPT, user_message)
            self.last_latency_s = time.perf_counter() - t0
            self.last_raw_response = text
            logger.info("Rationale évaluation réponse: %s", text)
            sanitized = self._sanitize(json.loads(text))
            self.last_fallback_reason = None
            return sanitized
        except Exception as exc:
            if self.last_latency_s is None:
                self.last_latency_s = time.perf_counter() - t0
            logger.warning("Rationale évaluation échoué (%s) — chaîne vide.", exc)
            self.last_fallback_reason = "call_or_parse_failed"
            return ""

    @staticmethod
    def _sanitize(raw_plan: dict) -> str:
        """Tronque ``rationale`` à :data:`MAX_RATIONALE_LENGTH` caractères.

        Aucune autre validation de contenu : ce champ n'influence rien en
        aval (lecture seule, purement explicatif).
        """
        raw = raw_plan if isinstance(raw_plan, dict) else {}
        rationale = str(raw.get("rationale", ""))
        return rationale[:MAX_RATIONALE_LENGTH]
