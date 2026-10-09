"""Couche LLM de RAFFINEMENT D'ORDRE des ports d'attaque — jamais un remplacement.

STRICT separation of concerns : ce composant affine ``target_ports`` déjà
fixés par :meth:`~nzoyi.agents.orchestrator.OrchestratorAgent._apply_plan`
(décision STRATÉGIQUE du LLM orchestrateur), en s'appuyant sur le triage
VulnAnalyzer (sévérité par port). Il ne remplace JAMAIS cette décision :
``_sanitize`` ne laisse passer qu'un port déjà présent dans ``target_ports``
OU associé à une vulnérabilité de sévérité ``critical`` du triage — jamais une
cible totalement inventée par le modèle, hors de ce que le pipeline a
réellement découvert.

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

logger = logging.getLogger("nzoyi.llm.attack_priority")

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "Tu es la couche de RAFFINEMENT D'ORDRE des cibles d'un pentest de lab "
    "isolé (recherche académique autorisée). Tu reçois les ports DÉJÀ "
    "sélectionnés par la couche stratégique et les vulnérabilités déjà "
    "triées par port. Tu ne peux QUE réordonner ces ports par priorité "
    "d'exploitation, et tu peux ÉVENTUELLEMENT ajouter un port non retenu "
    "SEULEMENT s'il porte une vulnérabilité de sévérité critical identifiée "
    "ci-dessous — jamais une cible que le pipeline n'a pas réellement "
    "découverte. Réponds UNIQUEMENT en JSON, sans texte, avec exactement ce "
    'schéma : {"ports_prioritaires": [int], "raison": str}.'
)


class AttackPriorityLLM:
    """Raffinement LLM de l'ordre des ports — ne remplace jamais la stratégie."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.0,
        enabled: bool = True,
        backend: LLMBackend | None = None,
    ) -> None:
        """Initialise la couche de raffinement.

        Args:
            model: Identifiant de modèle Anthropic. Si ``None``, résolu via
                ``NZOYI_ANTHROPIC_MODEL`` puis :data:`DEFAULT_MODEL`.
            temperature: Température d'échantillonnage (0.0 = raffinement déterministe).
            enabled: Quand ``False``, le LLM est contourné et ``target_ports``
                est conservé sans aucune modification.
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

    def decide(self, target_ports: list[int], findings: list[dict]) -> dict:
        """Affine l'ordre de ``target_ports`` en s'appuyant sur ``findings``.

        Args:
            target_ports: Ports déjà sélectionnés par la couche stratégique
                (:meth:`OrchestratorAgent._apply_plan`).
            findings: Findings triés du PTT (le plus récent nœud
                ``vuln_analysis``), utilisés pour identifier les ports
                porteurs d'une vulnérabilité ``critical``.

        Returns:
            Un plan validé ``{"ports_prioritaires": list[int], "raison": str}``.
            Repli déterministe (``target_ports`` inchangé) sur toute erreur,
            quand le LLM est désactivé/indisponible, ou quand la réponse ne
            laisse passer aucun port valide après filtrage.
        """
        if not self.enabled or self.backend is None:
            reason = "LLM désactivé" if not self.enabled else "backend indisponible"
            logger.info("Raffinement attaque contourné (%s) — ordre conservé.", reason)
            self.last_fallback_reason = "disabled" if not self.enabled else "backend_unavailable"
            return self._fallback(target_ports)

        user_message = json.dumps(
            {
                "target_ports": list(target_ports),
                "findings": [
                    {"port": f.get("port"), "cve_id": f.get("cve_id"), "severity": f.get("severity")}
                    for f in findings
                ],
            },
            ensure_ascii=False,
            default=str,
        )
        logger.info("Raffinement attaque prompt (%s): %s", self.model, user_message)

        t0 = time.perf_counter()
        try:
            text = self.backend.decide(SYSTEM_PROMPT, user_message)
            self.last_latency_s = time.perf_counter() - t0
            self.last_raw_response = text
            logger.info("Raffinement attaque réponse: %s", text)
            sanitized = self._sanitize(json.loads(text), target_ports, findings)
            self.last_fallback_reason = None
            return sanitized
        except Exception as exc:
            if self.last_latency_s is None:
                self.last_latency_s = time.perf_counter() - t0
            logger.warning("Raffinement attaque échoué (%s) — ordre conservé.", exc)
            self.last_fallback_reason = "call_or_parse_failed"
            return self._fallback(target_ports)

    @staticmethod
    def _sanitize(raw_plan: dict, target_ports: list[int], findings: list[dict]) -> dict:
        """Filtre ``ports_prioritaires`` : chaque port doit appartenir à
        ``target_ports`` OU porter une vulnérabilité ``critical`` de
        ``findings`` — jamais une cible hors de ce que le pipeline a
        réellement découvert. Si rien ne passe le filtre, ``target_ports``
        est conservé intact (jamais une liste vide inventée)."""
        raw = raw_plan if isinstance(raw_plan, dict) else {}
        raison = str(raw.get("raison", ""))
        ports_raw = raw.get("ports_prioritaires")

        allowed = set(target_ports) | {
            f.get("port")
            for f in findings
            if f.get("severity") == "critical" and f.get("port") is not None
        }

        ports_prioritaires: list[int] = []
        if isinstance(ports_raw, list):
            for p in ports_raw:
                try:
                    p_int = int(p)
                except (TypeError, ValueError):
                    continue
                if p_int in allowed and p_int not in ports_prioritaires:
                    ports_prioritaires.append(p_int)

        if not ports_prioritaires:
            ports_prioritaires = list(target_ports)

        return {"ports_prioritaires": ports_prioritaires, "raison": raison}

    @staticmethod
    def _fallback(target_ports: list[int]) -> dict:
        """Repli déterministe : ``target_ports`` conservé sans aucune modification."""
        plan = {"ports_prioritaires": list(target_ports), "raison": "fallback hors-ligne"}
        logger.info("Raffinement attaque fallback: ordre conservé %s", plan["ports_prioritaires"])
        return plan
