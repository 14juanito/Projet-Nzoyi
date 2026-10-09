"""Nettoyage pré-parsing partagé par les 4 rôles LLM (J7-ter).

Les backends LLM (Claude, modèles Ollama locaux) enveloppent très souvent
leur réponse JSON dans des fences markdown (``` ```json ... ``` ``` ou
``` ``` ... ``` ```), un habitude de formatage qui n'a rien à voir avec la
validité du contenu. Avant ce module, les 4 rôles (``orchestrator_llm``,
``vuln_triage_llm``, ``attack_priority_llm``, ``evaluation_rationale_llm``)
appelaient ``json.loads()`` directement sur le texte brut : une réponse par
ailleurs valide et cohérente échouait alors au parsing
(``json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)``)
et retombait sur le repli déterministe — à tort attribué, depuis J7, à une
« limite du modèle » plutôt qu'à ce bug de parsing (voir
``docs/evidence/j7-ter/README.md``, section « Vérifications complémentaires »).
"""

from __future__ import annotations

import re

#: Fence d'ouverture : ``` ``` `` suivi, optionnellement, d'un identifiant de
#: langage (``json``, ``JSON``, etc.) puis d'un retour à la ligne.
_FENCE_OPEN_RE = re.compile(r"^```[^\n]*\n?")
#: Fence de fermeture : ``` ``` `` seul, en fin de texte.
_FENCE_CLOSE_RE = re.compile(r"```$")


def strip_markdown_fences(text: str) -> str:
    """Retire les fences markdown (```json ... ``` ou ``` ... ```) entourant
    une réponse LLM, avant tout ``json.loads()``.

    Ne modifie jamais le CONTENU du JSON lui-même — uniquement l'enveloppe de
    formatage markdown. Un texte sans fences est renvoyé inchangé (hors
    ``strip()`` des espaces/retours à la ligne superflus en bordure).

    Args:
        text: Texte brut renvoyé par le backend LLM.

    Returns:
        Le texte nettoyé, prêt pour ``json.loads()``. Peut rester invalide si
        le JSON lui-même est malformé — cette fonction ne fait AUCUNE
        validation de contenu, seulement un retrait d'enveloppe.
    """
    cleaned = text.strip()
    cleaned = _FENCE_OPEN_RE.sub("", cleaned, count=1)
    cleaned = _FENCE_CLOSE_RE.sub("", cleaned.rstrip())
    return cleaned.strip()
