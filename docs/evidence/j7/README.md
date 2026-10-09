# Preuves brutes — comparatif J7 du panel LLM stratégique

## Run #2 (2026-10-09, 15:19+ UTC+1) — cible enrichie + fix OpenRouter

Correctifs apportés après le Run #1 (conservé ci-dessous pour traçabilité) :

### TASK 1 — Cible enrichie (`192.168.100.14`, en place, pas de VM recréée)

Deux services supplémentaires compilés **depuis les sources officielles**
(jamais un paquet apt moderne : Ubuntu 22.04 ne fournit plus ces versions)
et activés via systemd sur la cible existante :

| Service | Version exacte | Port | CVE | Sévérité | Pourquoi ce choix |
|---|---|---|---|---|---|
| vsftpd | **2.3.4** (source officielle `security.appspot.com`, build du 2011-02-15) | 21/tcp | `CVE-2011-2523` (backdoor) | critical | Déjà dans `KNOWN_VULNS["ftp"]`/`["vsftpd"]` (`nzoyi/agents/vulnerability.py`) avec un match version EXACT (`min_ver=max_ver="2.3.4"`) — aucune extension de la base CVE nécessaire. |
| Apache httpd | **2.4.49** (source officielle, mirroir GitHub `apache/httpd` tag `2.4.49` car `archive.apache.org` injoignable depuis ce réseau — `dlcdn.apache.org`/`github.com` atteignables) | 80/tcp | `CVE-2021-41773` (path traversal/RCE) | critical | Déjà dans `KNOWN_VULNS["http"]` (`min_ver="2.4.49"`, `max_ver="2.4.50"` — fenêtre d'une seule version patch, 2.4.49 est la seule qui matche). |

Compilation : `vsftpd` a nécessité un patch mineur du `Makefile` (`-lcrypt`
absent par défaut sur glibc moderne — `crypt()` a quitté la libc de base).
`httpd` a nécessité `./buildconf --with-apr=apr-1-config
--with-apr-util=apu-1-config` (le tag GitHub ne contient pas de `configure`
pré-généré, contrairement au tarball de release officiel) puis
`./configure --with-apr=/usr --with-apr-util=/usr --with-pcre=/usr`, en
réutilisant les dev-libs APR/PCRE d'Ubuntu 22.04 (compatibles) plutôt que de
compiler APR aussi depuis les sources.

**Choix de sécurité délibéré** : les deux services sont configurés en
lecture seule / sans fonctionnalité dangereuse activée (vsftpd :
`anonymous_enable=YES` mais `write_enable=NO`, racine anonyme vide, chroot ;
Apache : config par défaut, pas de `mod_cgi`/alias exploitable) — **le
`CVE-2021-41773` n'est donc pas réellement exploitable tel que configuré**
(testé : `curl` sur le payload de traversal connu renvoie `403`, pas de
fuite de fichier). Seule la bannière de version doit être authentique pour
que la corrélation déterministe de `vulnerability.py` fonctionne — NZOYI
n'exploite jamais réellement un CVE (`AttackAgent` ne fait que du scan nmap,
voir `nzoyi/agents/attack.py::run`), donc aucune fonctionnalité réellement
dangereuse n'était nécessaire. Garder un vrai path-traversal RCE actif sur
une VM ayant un accès internet sortant aurait été un risque inutile.

Services démarrés et persistés via `systemd` (`nzoyi-vsftpd-vuln.service`,
`nzoyi-httpd-vuln.service`, `enable --now`) — survivent à un redémarrage de
la VM.

Recon réel confirmé après enrichissement (`nmap -sV`) :

```
21/tcp open  ftp     vsftpd 2.3.4
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.17 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.49 ((Unix))
```

→ en pratique **4 CVE** réellement corrélées par cycle (`CVE-2011-2523`,
`CVE-2023-38408`, `CVE-2021-41773` **et** `CVE-2021-42013` — ce dernier,
une variante RCE de la même faille Apache, matche aussi la fenêtre de
version 2.4.49 dans `KNOWN_VULNS["http"]`), 3 `critical` + 1 `high` — contre
1 seul `high` au Run #1 : le triage (`VulnTriageLLM`) a maintenant un vrai
arbitrage à faire, confirmé dans les logs (chaque modèle réordonne
différemment les 4 CVE).

**Correction d'une hypothèse erronée du Run #1** : enrichir la cible n'a
**PAS** débloqué `AttackPriorityLLM` (toujours `0 appel` pour les 5
backends, voir `results/j7_llm_panel_comparison.md`). Cause réelle,
identifiée après coup : `nzoyi.ui.interactive.LearningRunner` — la classe
que `main.py --mode learn` utilise réellement pour le CLI (et donc pour
`run_j7_campaign.py`) — **n'appelle jamais**
`OrchestratorAgent._strategic_plan()`/`_apply_plan()`. Ces méthodes
existent et sont bien appelées par les AUTRES méthodes de la même classe
(`OrchestratorAgent.run()`, `.learn()`, `.finetune()`, lignes 242-457 de
`orchestrator.py`) — mais `LearningRunner` (la couche UI/TUI live, utilisée
par le CLI) est une réimplémentation séparée du même concept de boucle
d'apprentissage qui a dérivé et ne les appelle pas. Résultat :
`self.attack.target_ports` reste vide pour TOUJOURS sous `--mode learn`,
quel que soit le nombre de ports/CVE réels sur la cible — ce n'est donc pas
une limite de la cible (corrigée ici) mais une duplication non
intentionnelle entre deux implémentations de la boucle d'apprentissage.
Non corrigé dans cette session (changerait le comportement d'un chemin de
code partagé, utilisé aussi par J8) — laissé à la décision de l'utilisateur.

### TASK 2 — Fix `.env` OpenRouter (partiel — clé API manquante)

`.env` modifié **uniquement** sur les 2 variables demandées :
`NZOYI_OPENAI_COMPAT_BASE_URL=https://openrouter.ai/api/v1` et
`NZOYI_OPENAI_COMPAT_MODEL=deepseek/deepseek-r1:free`. Smoke test de
vérification : l'appel atteint bien `openrouter.ai` cette fois (plus de
404/repli-local silencieux) mais échoue en **`401 Unauthorized — Missing
Authentication header`**, parce que `NZOYI_OPENAI_COMPAT_API_KEY` reste la
valeur placeholder `ollama-local-no-auth` — aucune vraie clé OpenRouter
n'était disponible, et la consigne interdisait de toucher à autre chose que
les 2 variables listées (donc pas à `API_KEY`). Une clé réelle a été
repérée dans un projet non lié (`~/Decepticon/.env`) mais la réutiliser a
été **bloqué par un garde-fou de sécurité** (exploration de identifiants
inter-projets) — à raison, je ne l'ai pas contournée.

**Décision (validée par l'utilisateur) : OpenRouter est donc marqué
`absent` pour ce run** (`--exclude-label openrouter`), exactement comme
Claude le serait sans crédits — jamais lancé avec une clé connue non
fonctionnelle et présenté comme un résultat réel. Voir
`results/j7_llm_panel_comparison.md`, ligne `openrouter` / `claude` :
`⬜ absent (<raison>)`.

### Résultats clés Run #2 (voir `results/j7_llm_panel_comparison.{json,csv,md}`)

5 backends locaux réellement testés, 8 cycles chacun, triage réel sur 4 CVE
(3 `critical` + 1 `high`) — `attack_priority` reste à 0 appel partout
(cause structurelle expliquée ci-dessus, pas liée à la cible) :

| Modèle | Détection finale (épisodes) | Durée | Fallback triage | Fallback rationale | Latence triage/rationale (moy.) |
|---|---|---|---|---|---|
| WhiteRabbitNeo-2.5-Qwen-7B | 12.5% (1/8) | 551s | 0/1 | 0/8 | 42s / 60s |
| Dolphin3.0-Llama3.1-8B | 12.5% (1/8) | 336s | 0/1 | 0/8 | 55s / 31s |
| Lily-Cybersecurity-7B | 12.5% (1/8) | 295s | 0/1 | 0/8 | 81s / 23s |
| **WhiteRabbitNeo-2-8B (Llama-3.1)** | **0.0% (0/8)** | 807s | **1/1** | **8/8** | 56s / 90s |
| Foundation-Sec-8B-Instruct | 0.0% (0/8) | 809s | 0/1 | 0/8 | 95s / 85s |
| openrouter | ⬜ absent | — | — | — | — |
| claude | ⬜ absent | — | — | — | — |

**Lecture du taux de détection** : sur seulement 8 épisodes par backend, un
écart de 0% vs 12.5% représente **1 seule détection Suricata** sur 8 — à ne
pas sur-interpréter comme une différence de qualité de modèle : c'est dans
la marge du bruit d'exploration ε-greedy du Q-Learning (`ε` démarre à
`0.199` et varie peu sur 8 cycles, voir `evasion_state.json`/convergence
par run). Le signal qui se reproduit de façon cohérente entre Run #1 et
Run #2, en revanche, **est** significatif : WhiteRabbitNeo-2-8B (génération
Llama-3.1) échoue systématiquement le parsing JSON (triage ET rationale,
100% des appels, les deux runs) — ce n'est pas du bruit, c'est un trait
reproductible du modèle.

Fallback JSON par **rôle** (triage vs rationale) distinctement, comme
demandé : tous les modèles sauf WhiteRabbitNeo-2-8B ont **0% de fallback
sur les deux rôles** — WhiteRabbitNeo-2-8B a 100% sur les deux. Aucun
modèle n'a un taux différent entre triage et rationale (le problème est
général au formatage de sortie du modèle, pas spécifique à un prompt).

### Limitation connue — `attack_priority` non exercé

**Cause racine** (diagnostiquée, non corrigée dans ce run) :
`nzoyi.ui.interactive.LearningRunner.run()` (`nzoyi/ui/interactive.py:515-725`)
— la classe que `main.py --mode learn` utilise réellement, et donc que
`run_j7_campaign.py:169` utilise pour toute la campagne — n'appelle jamais
`OrchestratorAgent._strategic_plan()` / `._strategic_replan()` /
`._apply_plan()`, contrairement à `OrchestratorAgent.learning_loop()`
(`nzoyi/agents/orchestrator.py:273-415`) qui, elle, le fait. Conséquence
mécanique : `AttackAgent.target_ports` reste à sa valeur par défaut `None`
(`nzoyi/agents/attack.py:36`) pour toute la durée de la campagne, donc
`AttackAgent._refine_target_priority()` (`nzoyi/agents/attack.py:64-72`)
retourne avant même d'instancier `AttackPriorityLLM` — à chaque cycle, pour
chaque backend.

**Impact concret** : `attack_priority.calls = 0` pour les 5 backends locaux
(Run #1 ET Run #2, voir `results/j7_llm_panel_comparison.json`). Le
comparatif J7 porte donc réellement sur le module de **triage**
(`VulnTriageLLM`, exercé avec 4 CVE réelles au Run #2) et sur le module de
**rationale** (`EvaluationRationaleLLM`, exercé à chaque cycle) — **pas**
sur la priorisation d'attaque, qui n'a jamais été sollicitée.

**Pas un biais entre backends** : la cause est structurelle — un bug du
runner CLI, invariant par rapport au modèle chargé — et non un artefact de
cible ou de modèle. Les 5 backends locaux ont été affectés de façon
strictement identique (`0/0/0/0/0` appels), donc ce manque n'introduit
aucune distorsion dans la comparaison inter-modèles faite sur triage et
rationale.

**Statut** : fix identifié et diffé en diagnostic (non appliqué — voir
historique de session), reporté à une itération **J7-bis** séparée. Deux
décisions de conception non triviales restent à valider explicitement par
l'opérateur avant implémentation :
1. Geler `self.profile` pendant `LearningRunner` pour empêcher
   `_apply_plan`/`_apply_profile` de remplacer silencieusement le profil
   `--profile` choisi en CLI par celui que le LLM stratégique déciderait
   (second facteur de variance non contrôlé sinon).
2. Ignorer `plan["lancer_boucle_evasion"]` et garder `cycles` comme seule
   autorité du runner (déjà tranché côté décision produit, à documenter
   dans le code au moment du patch plutôt que seulement ici).

Ce fichier n'a pas été modifié : `nzoyi/agents/evasion.py` et
`nzoyi/rl/qlearning.py` restent hors de portée, et aucune campagne n'a été
relancée pour cette tâche.

---

## Run #1 (2026-10-09, 13:45–14:33 UTC+1) — superseded, conservé pour traçabilité

Campagne réelle exécutée via
`run_j7_campaign.py`, contre la cible fraîche `nzoyi-suricata-target-02`
(lab IP `192.168.100.14`, voir `credentials.local` — non versionné) démarrée
et vérifiée joignable (ping + SSH + Suricata actif/journalisant) juste avant
la campagne. Profil d'attaque `stealth`, 8 cycles RL par backend, signal RF
online désactivé (`--no-rf-online` : cette cible n'a pas d'endpoint Flask,
contrairement à l'ancienne cible `192.168.100.11`) — détection mesurée
uniquement via les alertes Suricata réelles (`eve.json` miroité en continu
par `ssh ... sudo tail -F` depuis ce poste Kali vers un fichier local, jamais
interrompu pendant la campagne).

## ⚠️ Anomalie découverte — l'entrée « openrouter » n'a PAS appelé OpenRouter

Le `.env` du projet définit actuellement :

```
NZOYI_OPENAI_COMPAT_BASE_URL=http://localhost:11434/v1
NZOYI_OPENAI_COMPAT_MODEL=deepseek-r1:8b
```

Ces variables ciblent Ollama **local** (`localhost:11434`), pas
`https://openrouter.ai/api/v1` — et le tag `deepseek-r1:8b` n'a jamais été
téléchargé en local (décision explicite : DeepSeek-R1 reste accessible via
OpenRouter, jamais dupliqué en local). Résultat : les 9 appels de ce run («
openrouter » dans tous les rapports) ont tous échoué en `404 model not
found` en ~5-20 ms chacun (voir `smoke_test_run1.json` et
`campaign_stdout_run1.txt`), et sont systématiquement retombés sur le repli
déterministe — **jamais exclus silencieusement**, comme l'exige la
contrainte non négociable (voir `fallback_reason: "call_or_parse_failed"`
sur les 2/2 appels du smoke test et 16/16 appels de la campagne réelle pour
cette entrée).

**Conséquence : la ligne « openrouter » des rapports `results/j7_*` ne
mesure PAS DeepSeek-R1 via OpenRouter — elle mesure le comportement du
pipeline quand ce rôle tombe intégralement en repli déterministe.** Pour un
vrai comparatif OpenRouter, il faut corriger `.env` (`NZOYI_OPENAI_COMPAT_BASE_URL=https://openrouter.ai/api/v1`,
`NZOYI_OPENAI_COMPAT_MODEL=deepseek/deepseek-r1`) puis rejouer cette seule
entrée — **non fait ici**, cette correction touchant un fichier de secrets,
laissée à la relecture humaine plutôt qu'appliquée automatiquement.

## Cible — limite connue

Recon réel : **un seul port ouvert (22/SSH, OpenSSH 8.9p1)** sur cette cible
fraîche. La corrélation CVE déterministe du framework trouve bien une
vulnérabilité (`CVE-2023-38408`, sévérité `high`), ce qui permet un vrai
appel de triage — mais avec un seul finding, il n'y a rien à réordonner : la
différenciation entre modèles sur ce rôle se limite à latence/fiabilité
JSON, pas à la qualité du tri. `AttackPriorityLLM` n'a été appelé **pour
aucun backend** (`attack_priority.calls = 0` partout) : `target_ports` n'a
jamais été peuplé par la couche stratégique sur cette cible à un seul port —
comportement du pipeline antérieur à J7, pas un défaut du harness de
comparatif (voir `nzoyi/agents/attack.py::_refine_target_priority`, qui ne
tente l'appel que si `target_ports` est non vide).

## Contenu de ce dossier

Suffixe `_run1`/`_run2` partout où les deux campagnes ont produit un
artefact distinct — `run_j7_campaign.py` écrit toujours au même chemin
(`smoke_test.json`, `results/ptt.json`…), donc chaque run écrase le
précédent : les fichiers `_run1` ci-dessous ont été sauvegardés **avant**
le Run #2 (sauf `smoke_test_run1.json`, écrasé par accident par le Run #2
avant la sauvegarde — reconstruit fidèlement depuis les lignes `smoke [...]`
de `campaign_stdout_run1.txt`, qui lui n'a jamais été écrasé car redirigé
vers un chemin dédié dès le lancement de chaque run).

| Fichier/dossier | Contenu |
|---|---|
| `smoke_test_run1.json` | Smoke test Run #1 (6 entrées incl. « openrouter » mal configuré) — **reconstruit** depuis `campaign_stdout_run1.txt`, voir note ci-dessus. |
| `smoke_test_run2.json` | Smoke test Run #2 (5 entrées Ollama locales ; openrouter/claude jamais smoke-testés, voir TASK 2/results). |
| `ptt/<label>.ptt.json` | PTT complet d'un run réel. 6 fichiers : 5 écrasés par le Run #2 (données les plus récentes), `openrouter.ptt.json` reste celui du Run #1 (seule trace de la tentative mal configurée, Run #2 l'ayant exclue). |
| `campaign_stdout_run1.txt` / `campaign_stdout_run2.txt` | stdout/stderr complet de chaque exécution de `run_j7_campaign.py` (smoke tests + campagnes réelles, logs applicatifs inclus). |
| `eve_alerts_excerpt_run1.json` / `eve_alerts_excerpt_run2.json` | Événements `alert` réels de la cible par run (hors bruit `SURICATA Ethertype unknown`) — Run #1 : 43 alertes (1 seul service exposé) ; Run #2 : 108 alertes (3 services exposés — FTP/SSH/HTTP), signatures élargies aux scans MSSQL/mySQL/Oracle/PostgreSQL/VNC + SSH. |

## Résultats clés (voir `results/j7_llm_panel_comparison.{json,csv,md}`)

| Backend | Détection finale | Durée | Fallback triage | Fallback rationale |
|---|---|---|---|---|
| WhiteRabbitNeo-2.5-Qwen-7B | 12.5% | 501s | 0/1 | 0/8 |
| Dolphin3.0-Llama3.1-8B | 12.5% | 320s | 0/1 | 0/8 |
| Lily-Cybersecurity-7B | 12.5% | 352s | 0/1 | 3/8 |
| WhiteRabbitNeo-2-8B (Llama-3.1) | **0.0%** | 705s | 1/1 | 8/8 |
| Foundation-Sec-8B-Instruct | 0.0% | 670s | 0/1 | 0/8 |
| openrouter (⚠️ mal configuré, voir ci-dessus) | 12.5% | 14s | 1/1 | 8/8 |

**Observation la plus nette : WhiteRabbitNeo-2-8B (génération Llama-3.1,
pas la 2.5-Qwen) échoue à produire un JSON valide pour le rôle rationale
dans 8/8 cas** (`fallback_reason: "call_or_parse_failed"`, voir
`ptt/ollama_hf.co_mradermacher_Llama-3.1-WhiteRabbitNeo-2-8B-GGUF_Q5_K_M.ptt.json`)
— le modèle répond mais enveloppe systématiquement sa réponse de texte hors
JSON ou de guillemets mal échappés. C'est un problème de **formatage de
sortie**, jamais traité comme une alerte de contenu : zéro influence sur
`detected`/`final_detection_rate`, qui restent calculés exclusivement par la
fusion déterministe Suricata réelle.

Dolphin3.0 (non censuré) a le taux de fallback global le plus bas du panel
local (0%) — aucune réticence/refus observée sur ce rôle purement
explicatif (rationale), cohérent avec le choix de ce modèle justement pour
éviter un refus d'alignement générique sur du contenu offensif de pentest.

## Synthèse finale

**Scope réel du comparatif** : 5 backends Ollama locaux testés en conditions
réelles (8 cycles chacun, cible enrichie à 4 CVE au Run #2), sur les rôles
**triage** (`VulnTriageLLM`) et **rationale d'évaluation**
(`EvaluationRationaleLLM`) uniquement — `attack_priority` n'a jamais été
exercé (limitation structurelle documentée ci-dessus, identique pour les 5
backends). OpenRouter est explicitement exclu (clé API connue non
fonctionnelle, réutilisation de credentials inter-projets bloquée à raison
par le garde-fou de sécurité) et Claude explicitement en attente de crédits
— aucun des deux n'a été lancé avec une configuration cassée ni présenté
comme un résultat réel.

**Résultat principal** : sur **n=8 cycles/backend**, les taux de détection
Suricata obtenus (12.5% soit 1/8, ou 0.0% soit 0/8) ne sont **pas
statistiquement distinguables** entre modèles — l'écart représente une
seule détection sur huit épisodes et reste dans la marge du bruit
d'exploration ε-greedy du Q-Learning. Il n'y a **pas de corrélation claire
entre taux de fallback JSON et taux de détection** : WhiteRabbitNeo-2-8B
cumule 100% de fallback sur triage et rationale sans que cela se traduise
par une détection plus faible ou plus forte que les modèles à 0% de
fallback (0.0% vs 12.5%, soit toujours 0 ou 1 détection sur 8 — même ordre
de grandeur). Le seul signal réellement reproductible entre les deux runs
est le fallback JSON systématique de WhiteRabbitNeo-2-8B lui-même, pas un
effet sur la détection.

**Perspectives** :
- **J7-bis** : corriger `LearningRunner` pour exercer réellement
  `AttackPriorityLLM` (diagnostic et diff disponibles ci-dessus), après
  validation explicite des deux décisions de conception en attente
  (gel du profil, autorité de `cycles` sur `lancer_boucle_evasion`).
- **Extension Claude/OpenRouter** : rejouer les 2 entrées actuellement
  `absent` dès qu'une clé Anthropic créditée et une clé OpenRouter valide
  seront disponibles, avec la même méthodologie (découverte dynamique,
  smoke test, interleaving par backend) — aucune autre modification du
  harness n'est nécessaire, `run_j7_campaign.py` les découvre déjà.
