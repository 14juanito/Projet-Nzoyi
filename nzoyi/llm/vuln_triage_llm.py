"""Couche LLM de TRIAGE des vulnérabilités — réordonne, n'invente jamais.

STRICT separation of concerns : ce composant ne fait QUE réordonner/prioriser
les findings déjà trouvés par la corrélation CVE locale déterministe
(:mod:`nzoyi.agents.vulnerability`). Il n'ajoute, ne modifie ni ne supprime
AUCUN contenu de finding — seulement leur ORDRE. ``_sanitize`` garantit que
tout identifiant inconnu renvoyé par le modèle est ignoré, et que tout
``cve_id`` réellement trouvé mais omis par le modèle est rajouté à la fin :
aucune vulnérabilité détectée ne peut jamais disparaître du résultat final à
cause d'un oubli du LLM.

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

logger = logging.getLogger("nzoyi.llm.vuln_triage")

DEFAULT_MODEL = "claude-sonnet-5"

# Sévérité -> rang pour le repli déterministe (plus petit = plus prioritaire).
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SYSTEM_PROMPT = (
    "Tu es la couche de TRIAGE des vulnérabilités d'un pentest de lab isolé "
    "(recherche académique autorisée). Tu reçois une liste de vulnérabilités "
    "déjà détectées par une corrélation CVE déterministe — tu ne dois JAMAIS "
    "en inventer de nouvelles ni en supprimer, seulement les RÉORDONNER par "
    "priorité d'exploitation (sévérité, facilité d'exploitation). Réponds "
    "UNIQUEMENT en JSON, sans texte, avec exactement ce schéma : "
    '{"ordre_cve_ids": [str], "raison": str}, où chaque élément de '
    "ordre_cve_ids est un identifiant (cve_id ou id applicatif, ex. "
    "DVWA-SQLI) pris EXCLUSIVEMENT parmi ceux de la liste fournie."
)


class VulnTriageLLM:
    """Triage LLM des findings de vulnérabilité — réordonne, n'invente rien."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.0,
        enabled: bool = True,
        backend: LLMBackend | None = None,
    ) -> None:
        """Initialise la couche de triage.

        Args:
            model: Identifiant de modèle Anthropic. Si ``None``, résolu via
                ``NZOYI_ANTHROPIC_MODEL`` puis :data:`DEFAULT_MODEL` (même
                logique que la couche stratégique).
            temperature: Température d'échantillonnage (0.0 = triage déterministe).
            enabled: Quand ``False``, le LLM est contourné et le repli
                déterministe (tri par sévérité) est toujours utilisé.
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

    def decide(self, findings: list[dict]) -> list[dict]:
        """Réordonne ``findings`` par priorité LLM — ne modifie jamais leur contenu.

        Args:
            findings: Findings déjà trouvés par la corrélation CVE locale
                déterministe (chaque dict porte au moins une clé ``cve_id``).

        Returns:
            Les MÊMES dicts (jamais copiés ni modifiés), réordonnés selon le
            triage LLM si disponible ; sinon selon le repli déterministe
            (sévérité critical > high > medium > low, puis ordre d'apparition).
        """
        if not findings:
            return []

        if not self.enabled or self.backend is None:
            reason = "LLM désactivé" if not self.enabled else "backend indisponible"
            logger.info("Triage vuln contourné (%s) — repli déterministe.", reason)
            self.last_fallback_reason = "disabled" if not self.enabled else "backend_unavailable"
            return self._fallback(findings)

        user_message = json.dumps(
            [
                {
                    "cve_id": f.get("cve_id"),
                    "severity": f.get("severity"),
                    "type": f.get("type"),
                    "port": f.get("port"),
                    "service": f.get("service"),
                }
                for f in findings
            ],
            ensure_ascii=False,
            default=str,
        )
        logger.info("Triage vuln prompt (%s): %s", self.model, user_message)

        t0 = time.perf_counter()
        try:
            text = self.backend.decide(SYSTEM_PROMPT, user_message)
            self.last_latency_s = time.perf_counter() - t0
            self.last_raw_response = text
            logger.info("Triage vuln réponse: %s", text)
            sanitized = self._sanitize(json.loads(text), findings)
            self.last_fallback_reason = None
            return sanitized
        except Exception as exc:
            if self.last_latency_s is None:
                self.last_latency_s = time.perf_counter() - t0
            logger.warning("Triage vuln échoué (%s) — repli déterministe.", exc)
            self.last_fallback_reason = "call_or_parse_failed"
            return self._fallback(findings)

    @staticmethod
    def _sanitize(raw_plan: dict, findings: list[dict]) -> list[dict]:
        """Valide ``ordre_cve_ids`` contre les findings réellement trouvés.

        Tout id absent de ``findings`` est ignoré. Tout ``cve_id`` de
        ``findings`` non mentionné par le modèle est rajouté à la fin, dans
        son ordre d'apparition d'origine — jamais de vulnérabilité perdue.
        """
        raw = raw_plan if isinstance(raw_plan, dict) else {}
        ordre_raw = raw.get("ordre_cve_ids")

        ordered: list[dict] = []
        used: set[int] = set()

        if isinstance(ordre_raw, list):
            for cve_id in ordre_raw:
                if not isinstance(cve_id, str):
                    continue
                for i, finding in enumerate(findings):
                    if i in used:
                        continue
                    if finding.get("cve_id") == cve_id:
                        ordered.append(finding)
                        used.add(i)
                        break

        # Tout finding connu non couvert par la réponse LLM -> rajouté à la
        # fin, dans l'ordre d'apparition d'origine (jamais perdu).
        for i, finding in enumerate(findings):
            if i not in used:
                ordered.append(finding)
                used.add(i)

        return ordered

    @staticmethod
    def _fallback(findings: list[dict]) -> list[dict]:
        """Tri déterministe : sévérité (critical > high > medium > low), puis
        ordre d'apparition d'origine (tri stable — aucune vulnérabilité
        réordonnée arbitrairement entre findings de même sévérité)."""
        indexed = list(enumerate(findings))
        indexed.sort(key=lambda pair: (_SEVERITY_RANK.get(pair[1].get("severity"), 99), pair[0]))
        ordered = [finding for _, finding in indexed]
        logger.info("Triage vuln fallback: tri déterministe (%d findings).", len(ordered))
        return ordered
