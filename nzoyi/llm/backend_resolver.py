"""Résolution partagée du backend LLM pour tout le panel (Orchestrator +
VulnTriage + AttackPriority + EvaluationRationale).

Il n'y a qu'UN SEUL fournisseur LLM configuré pour tout le framework (via
``NZOYI_LLM_PROVIDER`` et consorts) — chaque rôle (stratégique, triage,
raffinement, rationale) ne fait que lui poser des questions différentes, avec
son propre prompt/schéma/validation/repli. Ce module centralise donc la seule
partie réellement commune : lire ``NZOYI_LLM_PROVIDER``, construire le bon
:class:`~nzoyi.llm.backend.LLMBackend` (``AnthropicBackend`` ou
``OpenAICompatibleBackend``), et gérer clé API absente / provider invalide —
exactement la logique qui vivait auparavant dans
``LLMOrchestrator.__init__`` (J1/J2), extraite ici à l'identique pour que les
3 nouvelles couches (J5/J6) la réutilisent sans dupliquer ni dévier.

``env_prefix`` ne nomme QUE la variable de modèle propre à un rôle quand le
provider résolu est ``"anthropic"`` (ex. ``"ANTHROPIC"`` pour la couche
stratégique -> ``NZOYI_ANTHROPIC_MODEL``, inchangé depuis J1). Pour
``"openai_compatible"``, toute la configuration (``base_url``/modèle/clé/
``reasoning_effort``/``max_tokens``) reste globale au panel
(``NZOYI_OPENAI_COMPAT_*``) — un seul Ollama/OpenRouter configuré sert les 4
rôles.
"""

from __future__ import annotations

import logging
import os

from nzoyi.llm.backend import LLMBackend, LLMBackendError
from nzoyi.llm.backends.anthropic_backend import AnthropicBackend
from nzoyi.llm.backends.openai_compat_backend import OpenAICompatibleBackend

logger = logging.getLogger("nzoyi.llm.backend_resolver")

VALID_PROVIDERS = {"anthropic", "openai_compatible"}
DEFAULT_PROVIDER = "anthropic"
DEFAULT_OPENAI_COMPAT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_OPENAI_COMPAT_MODEL = "deepseek/deepseek-r1"
# Les modèles "thinking" (DeepSeek-R1 et consorts, servis via Ollama en local)
# peuvent épuiser tout leur budget de tokens en raisonnement interne avant
# d'émettre le JSON final — un `max_tokens` trop court renvoie alors un
# contenu vide, traité comme un échec (repli déterministe). 4096 par défaut
# laisse la marge nécessaire ; indépendant du `max_tokens=1024` d'
# `AnthropicBackend`, qui n'est pas concerné par cette variable.
DEFAULT_OPENAI_COMPAT_MAX_TOKENS = 4096


def resolve_backend(
    explicit_backend: LLMBackend | None,
    model_override: str | None,
    temperature: float,
    default_model: str,
    env_prefix: str,
) -> tuple[LLMBackend | None, str | None, str]:
    """Résout le backend LLM à utiliser pour un rôle donné du panel.

    Reproduit EXACTEMENT la logique qui vivait dans
    ``LLMOrchestrator.__init__`` (J1/J2) : si ``explicit_backend`` est fourni,
    il est retourné tel quel sans résolution de provider (c'est ce qui permet
    aux tests d'injecter un faux backend sans toucher à l'environnement).
    Sinon, lit ``NZOYI_LLM_PROVIDER`` (repli sur ``"anthropic"`` — avec
    warning — si absent ou invalide, jamais d'exception), puis construit
    ``AnthropicBackend`` ou ``OpenAICompatibleBackend`` selon le cas. Si la
    clé API du provider résolu est absente, ou si la construction échoue
    (``LLMBackendError``), le backend retourné est ``None`` — l'appelant
    retombe alors sur son propre repli déterministe.

    Args:
        explicit_backend: Backend déjà construit à utiliser en priorité
            (injection directe, ignore toute résolution de provider).
        model_override: Modèle explicitement demandé par l'appelant (prime
            sur la variable d'environnement propre au rôle, côté "anthropic"
            uniquement — côté "openai_compatible" le modèle est toujours
            celui de la configuration globale du panel).
        temperature: Température d'échantillonnage transmise au backend.
        default_model: Modèle par défaut si ni ``model_override`` ni la
            variable d'environnement propre au rôle ne sont définis
            (provider "anthropic" uniquement).
        env_prefix: Préfixe de la variable de modèle propre à ce rôle quand
            le provider résolu est "anthropic" (ex. ``"ANTHROPIC"`` ->
            ``NZOYI_ANTHROPIC_MODEL``).

    Returns:
        Un triplet ``(backend, provider, model)`` :
        ``backend`` est le :class:`LLMBackend` construit, ou ``None`` si
        indisponible ; ``provider`` est le provider résolu (``None`` si
        ``explicit_backend`` a été utilisé, car la résolution est alors
        sautée — comme avant le refactor) ; ``model`` est le nom de modèle
        résolu (utile pour le logging de l'appelant).
    """
    if explicit_backend is not None:
        return explicit_backend, None, model_override or default_model

    provider = os.environ.get("NZOYI_LLM_PROVIDER", DEFAULT_PROVIDER)
    if provider not in VALID_PROVIDERS:
        logger.warning(
            "NZOYI_LLM_PROVIDER invalide (%r) — repli sur %r.", provider, DEFAULT_PROVIDER
        )
        provider = DEFAULT_PROVIDER

    if provider == "anthropic":
        model = model_override or os.environ.get(f"NZOYI_{env_prefix}_MODEL", default_model)
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        backend: LLMBackend | None = None
        if api_key:
            try:
                backend = AnthropicBackend(model=model, temperature=temperature, api_key=api_key)
            except LLMBackendError as exc:
                logger.warning("Init backend Anthropic échouée: %s", exc)
                backend = None
        return backend, provider, model

    # provider == "openai_compatible" : configuration globale au panel.
    base_url = os.environ.get("NZOYI_OPENAI_COMPAT_BASE_URL", DEFAULT_OPENAI_COMPAT_BASE_URL)
    model = os.environ.get("NZOYI_OPENAI_COMPAT_MODEL", DEFAULT_OPENAI_COMPAT_MODEL)
    api_key = os.environ.get("NZOYI_OPENAI_COMPAT_API_KEY")
    reasoning_effort = os.environ.get("NZOYI_OPENAI_COMPAT_REASONING_EFFORT")
    try:
        max_tokens = int(
            os.environ.get("NZOYI_OPENAI_COMPAT_MAX_TOKENS", DEFAULT_OPENAI_COMPAT_MAX_TOKENS)
        )
    except (TypeError, ValueError):
        logger.warning(
            "NZOYI_OPENAI_COMPAT_MAX_TOKENS invalide — repli sur %d.",
            DEFAULT_OPENAI_COMPAT_MAX_TOKENS,
        )
        max_tokens = DEFAULT_OPENAI_COMPAT_MAX_TOKENS

    backend = None
    if api_key:
        try:
            backend = OpenAICompatibleBackend(
                base_url=base_url,
                model=model,
                api_key=api_key,
                temperature=temperature,
                reasoning_effort=reasoning_effort,
                max_tokens=max_tokens,
            )
        except LLMBackendError as exc:
            logger.warning("Init backend OpenAI-compatible échouée: %s", exc)
            backend = None
    return backend, provider, model
