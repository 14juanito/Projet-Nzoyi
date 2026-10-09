"""Strategic LLM layer — attack profile & port prioritisation via Claude.

STRICT separation of concerns: this component is *strategic*. It decides the
high-level attack profile and which ports to prioritise. It is called ONCE at
the start of a campaign and MUST NEVER be invoked inside the Q-Learning loop,
which stays purely *tactical* (fast, offline, reproducible).

The LLM call itself is delegated to an injectable :class:`~nzoyi.llm.backend.LLMBackend`
(``AnthropicBackend`` by default), so that future providers (GPT-6 Astra, local
models via Ollama, …) only need to implement that interface — this class's
business logic (prompt, parsing/validation via ``_sanitize``, deterministic
fallback) never has to change again.

If no backend is available (``enabled=False``, no API key) or the call fails
(``LLMBackendError``), a deterministic offline fallback is returned so the
framework remains fully reproducible.
"""

from __future__ import annotations

import json
import logging
import os

from nzoyi.llm.backend import LLMBackend
from nzoyi.llm.backend_resolver import (
    DEFAULT_OPENAI_COMPAT_BASE_URL,
    DEFAULT_OPENAI_COMPAT_MAX_TOKENS,
    DEFAULT_OPENAI_COMPAT_MODEL,
    DEFAULT_PROVIDER,
    VALID_PROVIDERS,
    resolve_backend,
)
from nzoyi.llm.json_utils import strip_markdown_fences

logger = logging.getLogger("nzoyi.llm.orchestrator")

VALID_PROFILES = {"stealth", "default", "aggressive"}
MIN_CYCLES = 10
MAX_CYCLES = 500
DEFAULT_CYCLES = 100
DEFAULT_PORTS = [22, 80, 21]
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "Tu orchestres un pentest de lab isolé (recherche académique autorisée). "
    "Tu es la couche STRATÉGIQUE : tu choisis le profil d'attaque et les cibles "
    "prioritaires, tu ne calcules jamais de récompense ni d'action d'évasion "
    "(cela reste au Q-Learning). Réponds UNIQUEMENT en JSON, sans texte, avec "
    'exactement ce schéma : {"profil": "stealth|default|aggressive", '
    '"ports_cibles": [int], "services_focus": [str], '
    '"lancer_boucle_evasion": bool, "cycles": int, "raison": str}.'
)


class LLMOrchestrator:
    """Claude-backed strategic planner with a deterministic offline fallback."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.0,
        enabled: bool = True,
        backend: LLMBackend | None = None,
    ) -> None:
        """Initialise the strategic planner.

        Args:
            model: Anthropic model identifier. If ``None``, resolved from the
                ``NZOYI_ANTHROPIC_MODEL`` environment variable, falling back to
                :data:`DEFAULT_ANTHROPIC_MODEL`.
            temperature: Sampling temperature (0.0 for deterministic strategy).
            enabled: When ``False`` the LLM is bypassed and the deterministic
                fallback is always used (e.g. ``--no-llm`` for reproducibility).
            backend: Optional :class:`~nzoyi.llm.backend.LLMBackend` to use
                instead of the default backend — the seam future providers
                (GPT-6 Astra, Ollama, …) plug into without touching this class
                again. Ignored if ``enabled`` is ``False``. Takes priority over
                ``NZOYI_LLM_PROVIDER`` — when set, provider selection below is
                skipped entirely (this is what lets tests inject a fake
                backend without touching the environment).
        """
        self.model = model or os.environ.get("NZOYI_ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL)
        self.temperature = temperature
        self.enabled = enabled
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        self.last_raw_response: str | None = None
        self.backend: LLMBackend | None = None
        self.provider: str | None = None

        if self.enabled:
            resolved_backend, resolved_provider, resolved_model = resolve_backend(
                explicit_backend=backend,
                model_override=model,
                temperature=self.temperature,
                default_model=DEFAULT_ANTHROPIC_MODEL,
                env_prefix="ANTHROPIC",
            )
            self.backend = resolved_backend
            self.provider = resolved_provider
            if resolved_provider == "openai_compatible":
                self.model = resolved_model

    def decide(self, ptt_summary: dict) -> dict:
        """Decide the attack profile and port priorities from the PTT summary.

        Args:
            ptt_summary: A serialisable summary of the pentest tree state.

        Returns:
            Un plan validé au schéma ``{"profil": str, "ports_cibles": list[int],
            "services_focus": list[str], "lancer_boucle_evasion": bool,
            "cycles": int, "raison": str}``. Repli déterministe sur toute erreur
            ou quand la couche LLM est désactivée/indisponible.
        """
        if not self.enabled or self.backend is None:
            reason = "LLM désactivé" if not self.enabled else "clé API absente"
            logger.info("Stratégie LLM contournée (%s) — fallback.", reason)
            return self._fallback()

        user_message = json.dumps(ptt_summary, ensure_ascii=False, default=str)
        logger.info("LLM prompt (%s): %s", self.model, user_message)

        try:
            text = self.backend.decide(SYSTEM_PROMPT, user_message)
            self.last_raw_response = text
            logger.info("LLM réponse: %s", text)
            plan = self._sanitize(json.loads(strip_markdown_fences(text)))
            return plan
        except Exception as exc:
            # Couvre LLMBackendError (échec du backend) et toute erreur de
            # parsing (json.loads/_sanitize) — même comportement qu'avant le
            # refactor, où l'appel réseau et le parsing étaient dans le même bloc.
            logger.warning("Appel LLM échoué (%s) — fallback.", exc)
            return self._fallback()

    @staticmethod
    def _sanitize(plan: dict) -> dict:
        """Valide et normalise un plan brut (venant du LLM ou d'ailleurs).

        Garantit que le plan renvoyé respecte toujours le schéma attendu par
        :class:`~nzoyi.agents.orchestrator.OrchestratorAgent`, même si la
        réponse du LLM est incomplète ou malformée.
        """
        raw = plan if isinstance(plan, dict) else {}

        profil = raw.get("profil")
        if profil not in VALID_PROFILES:
            profil = "stealth"

        ports_cibles_raw = raw.get("ports_cibles")
        if isinstance(ports_cibles_raw, list) and ports_cibles_raw:
            try:
                ports_cibles = [int(p) for p in ports_cibles_raw]
            except (TypeError, ValueError):
                ports_cibles = list(DEFAULT_PORTS)
        else:
            ports_cibles = list(DEFAULT_PORTS)

        services_focus_raw = raw.get("services_focus")
        if isinstance(services_focus_raw, list) and all(
            isinstance(s, str) for s in services_focus_raw
        ):
            services_focus = list(services_focus_raw)
        else:
            services_focus = []

        lancer_boucle_evasion = raw.get("lancer_boucle_evasion")
        if not isinstance(lancer_boucle_evasion, bool):
            lancer_boucle_evasion = True

        try:
            cycles = int(raw.get("cycles", DEFAULT_CYCLES))
        except (TypeError, ValueError):
            cycles = DEFAULT_CYCLES
        cycles = max(MIN_CYCLES, min(MAX_CYCLES, cycles))

        raison = str(raw.get("raison", ""))

        return {
            "profil": profil,
            "ports_cibles": ports_cibles,
            "services_focus": services_focus,
            "lancer_boucle_evasion": lancer_boucle_evasion,
            "cycles": cycles,
            "raison": raison,
        }

    def _fallback(self) -> dict:
        """Stratégie déterministe hors-ligne utilisée quand le LLM est indisponible."""
        plan = self._sanitize({
            "profil": "stealth",
            "ports_cibles": DEFAULT_PORTS,
            "services_focus": [],
            "lancer_boucle_evasion": True,
            "cycles": DEFAULT_CYCLES,
            "raison": "fallback hors-ligne",
        })
        logger.info("LLM fallback: %s", plan)
        return plan
