"""Découverte dynamique du panel LLM — comparatif J7.

Jamais de nom de modèle local codé en dur : les modèles Ollama installés
sont découverts via l'API native Ollama (``GET /api/tags``), exactement la
même requête que ``main.py::_prompt_llm_model_menu`` (menu interactif
J3/J4) — ce module factorise cette découverte pour un usage non interactif
(campagne), et ``main.py`` la réutilise désormais au lieu de la dupliquer.

Claude et OpenRouter restent strictement optionnels : une entrée n'est
ajoutée au panel que si sa clé API est présente dans l'environnement
courant, et aucune absence de clé/backend ne lève jamais d'exception — le
run complet doit fonctionner avec un panel partiel (voire uniquement local)
sans erreur bloquante, exactement comme :func:`nzoyi.llm.backend_resolver.resolve_backend`.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import requests

from nzoyi.llm.backend import LLMBackend, LLMBackendError
from nzoyi.llm.backends.anthropic_backend import AnthropicBackend
from nzoyi.llm.backends.openai_compat_backend import OpenAICompatibleBackend

logger = logging.getLogger("nzoyi.llm.panel_discovery")

DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_OPENROUTER_MODEL = "deepseek/deepseek-r1"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5"
# Ollama ignore la clé API mais le client `openai` exige une valeur non vide
# pour construire le header Authorization — jamais une vraie clé, jamais
# loggée (identique à un placeholder, pas un secret).
OLLAMA_PLACEHOLDER_API_KEY = "ollama-local-no-auth"


@dataclass(frozen=True)
class PanelEntry:
    """Une entrée découverte du panel LLM, pas encore un backend construit.

    ``label`` est l'identifiant stable utilisé dans tous les artefacts/
    rapports du comparatif J7 (évite de rejouer la logique de nommage à
    chaque endroit qui consomme le panel).
    """

    label: str
    provider: str  # "anthropic" ou "openai_compatible"
    model: str
    base_url: str | None  # None pour "anthropic"
    api_key: str | None


def discover_ollama_models(
    base_url: str = DEFAULT_OLLAMA_BASE_URL, timeout: float = 3.0
) -> list[str]:
    """Liste les modèles Ollama installés localement via l'API native.

    Args:
        base_url: URL de base du serveur Ollama natif (pas l'endpoint
            compatible OpenAI — ``/v1`` n'est ajouté que par les appelants
            qui construisent un :class:`OpenAICompatibleBackend`).
        timeout: Timeout réseau en secondes.

    Returns:
        Les noms de modèles (``name`` de chaque entrée ``models``), ou une
        liste vide si Ollama n'est pas lancé, injoignable, ou renvoie une
        réponse inattendue — jamais d'exception propagée (même discipline
        que :func:`~nzoyi.llm.backend_resolver.resolve_backend`).
    """
    try:
        response = requests.get(f"{base_url}/api/tags", timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.warning(
            "Ollama injoignable sur %s (%s) — aucun modèle local découvert.", base_url, exc
        )
        return []
    try:
        return [m["name"] for m in response.json().get("models", [])]
    except (ValueError, KeyError, TypeError) as exc:
        logger.warning(
            "Réponse Ollama /api/tags inattendue (%s) — aucun modèle local découvert.", exc
        )
        return []


def discover_panel(ollama_base_url: str = DEFAULT_OLLAMA_BASE_URL) -> list[PanelEntry]:
    """Découvre dynamiquement tout le panel LLM disponible pour ce run.

    Trois sources, chacune strictement optionnelle :

    - Local (Ollama) : une entrée par modèle renvoyé par
      :func:`discover_ollama_models` — jamais une liste figée.
    - OpenRouter : une entrée si ``NZOYI_OPENAI_COMPAT_API_KEY`` est présente
      dans l'environnement (réutilise ``NZOYI_OPENAI_COMPAT_BASE_URL``/
      ``NZOYI_OPENAI_COMPAT_MODEL`` si définies, sinon les défauts OpenRouter
      du panel — voir :mod:`nzoyi.llm.backend_resolver`).
    - Claude : une entrée si ``ANTHROPIC_API_KEY`` est présente.

    Returns:
        La liste des entrées disponibles, dans cet ordre (local puis cloud).
        Peut être vide si rien n'est disponible — c'est à l'appelant de
        décider quoi faire d'un panel vide, jamais à cette fonction.
    """
    entries: list[PanelEntry] = []

    for model in discover_ollama_models(ollama_base_url):
        entries.append(
            PanelEntry(
                label=f"ollama:{model}",
                provider="openai_compatible",
                model=model,
                base_url=f"{ollama_base_url}/v1",
                api_key=OLLAMA_PLACEHOLDER_API_KEY,
            )
        )

    openrouter_key = os.environ.get("NZOYI_OPENAI_COMPAT_API_KEY")
    if openrouter_key:
        entries.append(
            PanelEntry(
                label="openrouter",
                provider="openai_compatible",
                model=os.environ.get("NZOYI_OPENAI_COMPAT_MODEL", DEFAULT_OPENROUTER_MODEL),
                base_url=os.environ.get(
                    "NZOYI_OPENAI_COMPAT_BASE_URL", DEFAULT_OPENROUTER_BASE_URL
                ),
                api_key=openrouter_key,
            )
        )

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        entries.append(
            PanelEntry(
                label="claude",
                provider="anthropic",
                model=os.environ.get("NZOYI_ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL),
                base_url=None,
                api_key=anthropic_key,
            )
        )

    return entries


def build_backend(entry: PanelEntry) -> LLMBackend | None:
    """Construit le backend LLM concret pour une entrée découverte.

    Args:
        entry: Entrée renvoyée par :func:`discover_panel`.

    Returns:
        Le backend construit, ou ``None`` si la construction échoue — jamais
        d'exception propagée (même discipline que
        :func:`~nzoyi.llm.backend_resolver.resolve_backend` : l'appelant
        retombe alors sur son propre repli déterministe).
    """
    try:
        if entry.provider == "anthropic":
            return AnthropicBackend(model=entry.model, temperature=0.0, api_key=entry.api_key)
        return OpenAICompatibleBackend(
            base_url=entry.base_url,
            model=entry.model,
            api_key=entry.api_key,
            temperature=0.0,
        )
    except LLMBackendError as exc:
        logger.warning("Construction du backend échouée pour %s: %s", entry.label, exc)
        return None


def env_overrides_for(entry: PanelEntry) -> dict[str, str]:
    """Construit les variables d'environnement à positionner pour que
    :func:`~nzoyi.llm.backend_resolver.resolve_backend` résolve CETTE entrée
    pour les 4 rôles du panel (stratégique/triage/raffinement/rationale), le
    temps d'une campagne complète pilotée par :mod:`run_j7_campaign`.

    Ne modifie jamais ``os.environ`` elle-même — c'est à l'appelant
    d'appliquer (et de restaurer) ces valeurs, pour qu'un échec de campagne
    ne laisse jamais l'environnement du process dans un état incohérent.
    """
    if entry.provider == "anthropic":
        return {
            "NZOYI_LLM_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": entry.api_key or "",
            "NZOYI_ANTHROPIC_MODEL": entry.model,
        }
    return {
        "NZOYI_LLM_PROVIDER": "openai_compatible",
        "NZOYI_OPENAI_COMPAT_BASE_URL": entry.base_url or DEFAULT_OPENROUTER_BASE_URL,
        "NZOYI_OPENAI_COMPAT_MODEL": entry.model,
        "NZOYI_OPENAI_COMPAT_API_KEY": entry.api_key or "",
    }
