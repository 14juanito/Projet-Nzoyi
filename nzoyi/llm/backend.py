"""Abstraction fournisseur-agnostique de la couche LLM stratégique.

Ce module définit le contrat que tout backend LLM doit respecter pour être
branché sur :class:`~nzoyi.llm.orchestrator_llm.LLMOrchestrator`. L'objectif est
d'isoler la logique métier de l'Orchestrator (construction du prompt, parsing et
validation du plan via ``_sanitize``, repli déterministe) du fournisseur concret
(Anthropic aujourd'hui ; GPT-6 Astra, modèles locaux via Ollama, etc. demain).

Un backend ne fait qu'une chose : renvoyer le *texte brut* de la réponse du
modèle. Il ne parse ni ne valide le JSON — cette responsabilité reste entièrement
dans :meth:`LLMOrchestrator._sanitize`, afin d'éviter toute duplication de la
logique de validation du plan.
"""

from __future__ import annotations

import abc


class LLMBackendError(Exception):
    """Erreur levée par un backend LLM quand l'appel au modèle échoue.

    L'appelant (:class:`~nzoyi.llm.orchestrator_llm.LLMOrchestrator`) attrape
    cette exception pour déclencher son repli déterministe existant. Les backends
    doivent envelopper toute défaillance (clé absente, erreur réseau, erreur API,
    dépendance manquante) dans cette exception plutôt que de laisser remonter
    l'exception d'origine du SDK sous-jacent.
    """


class LLMBackend(abc.ABC):
    """Contrat qu'un backend LLM doit implémenter pour l'Orchestrator.

    On utilise :class:`abc.ABC` avec :func:`abc.abstractmethod` (et non un
    ``typing.Protocol``) à dessein : un backend concret qui oublierait
    d'implémenter :meth:`decide` échouera explicitement et bruyamment à
    l'instanciation, plutôt que de passer silencieusement le typage statique.
    """

    @abc.abstractmethod
    def decide(self, system_prompt: str, user_message: str) -> str:
        """Interroge le modèle et renvoie le texte brut de sa réponse.

        Args:
            system_prompt: Instruction système (rôle, schéma de sortie attendu).
            user_message: Message utilisateur (résumé sérialisé du PTT).

        Returns:
            Le texte brut renvoyé par le modèle, sans aucun parsing. Le
            parsing/validation du plan est de la responsabilité exclusive de
            :meth:`LLMOrchestrator._sanitize`.

        Raises:
            LLMBackendError: En cas d'échec de l'appel (clé absente, erreur
                réseau, erreur API, dépendance manquante, …).
        """
        raise NotImplementedError
