<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:00ff41,100:0d1117&height=200&section=header&text=OpenZoyi&fontSize=64&fontAlignY=38&fontColor=39FF14&animation=fadeIn&desc=Multi-Agent%20Adaptive%20Intrusion%20Framework&descAlignY=58&descSize=17&descColor=39FF14" alt="OpenZoyi banner" width="100%">
</p>

<p align="center">
  <img src="assets/openzoyi-logo.png" alt="OpenZoyi — Multi-agent automated intrusion system" width="200">
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&duration=2800&pause=900&color=39FF14&center=true&vCenter=true&width=700&lines=%5B*%5D+Initialisation+du+Pentest+Tree+(PTT)...;%5B*%5D+Chargement+de+7+agents+sp%C3%A9cialis%C3%A9s...;%5B*%5D+Panel+LLM+%E2%80%94+Anthropic+%2F+OpenRouter+%2F+Ollama...;%5B*%5D+Evasion+Agent+%E2%80%94+Q-Learning+pur+(H1%2FH3)...;%5B*%5D+Analyse+des+alertes+Suricata+(eve.json)...;%5B%2B%5D+Syst%C3%A8me+multi-agents+op%C3%A9rationnel." alt="Typing SVG">
</p>

<p align="center">
  <strong>Système multi-agents d'intrusion automatisée avec évasion adaptative des IDS et panel LLM interchangeable</strong>
</p>

<p align="center">
  <a href="https://github.com/14juanito/Projet-Nzoyi"><img src="https://img.shields.io/badge/version-0.1.0-39FF14?style=flat-square&labelColor=0d1117" alt="Version"></a>
  <a href="https://github.com/14juanito/Projet-Nzoyi"><img src="https://img.shields.io/badge/python-3.11+-39FF14?style=flat-square&logo=python&logoColor=39FF14&labelColor=0d1117" alt="Python"></a>
  <a href="docs/LAB_SETUP.md"><img src="https://img.shields.io/badge/lab-isol%C3%A9-39FF14?style=flat-square&labelColor=0d1117" alt="Lab isolé"></a>
  <a href="#panel-llm-multi-fournisseur"><img src="https://img.shields.io/badge/LLM-Anthropic%20%7C%20OpenRouter%20%7C%20Ollama-39FF14?style=flat-square&labelColor=0d1117" alt="Panel LLM"></a>
  <a href="https://github.com/14juanito/Projet-Nzoyi"><img src="https://img.shields.io/badge/licence-recherche-39FF14?style=flat-square&labelColor=0d1117" alt="Licence"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/14juanito/Projet-Nzoyi?style=flat-square&color=39FF14&labelColor=0d1117" alt="Stars">
  <img src="https://img.shields.io/github/forks/14juanito/Projet-Nzoyi?style=flat-square&color=39FF14&labelColor=0d1117" alt="Forks">
  <img src="https://img.shields.io/github/last-commit/14juanito/Projet-Nzoyi?style=flat-square&color=39FF14&labelColor=0d1117" alt="Last commit">
  <img src="https://img.shields.io/github/issues/14juanito/Projet-Nzoyi?style=flat-square&color=39FF14&labelColor=0d1117" alt="Issues">
</p>

---

## Présentation

**NZOYI** (*Nzoyi* signifie « abeille » en lingala) est un framework de recherche en cybersécurité offensive conçu pour évaluer la robustesse des systèmes de détection d'intrusion (IDS) modernes — notamment **Suricata** — face à un attaquant qui **apprend** à s'adapter.

Contrairement aux outils de pentest classiques, NZOYI combine :

- une **architecture multi-agents** modulaire (7 agents spécialisés),
- un **Pentest Tree (PTT)** partagé pour conserver le contexte de l'opération,
- un **Evasion Agent** basé **exclusivement** sur le **Q-Learning** qui optimise timing, fragmentation et discrétion des scans — jamais de LLM dans cette boucle (voir [Pourquoi l'Evasion reste 100% RL](#pourquoi-lévasion-reste-100-rl)),
- un **panel LLM interchangeable** (Anthropic Claude, OpenRouter, ou modèles locaux via Ollama) qui assiste la couche stratégique, le triage des vulnérabilités, le raffinement de l'ordre d'attaque et l'explication des verdicts IDS,
- un **Evaluation Agent** qui lit le feedback des alertes IDS (Suricata `eve.json`) et fusionne avec un détecteur ML.

> Projet de fin de cycle — Faculté des Sciences Informatiques, Université Protestante au Congo (UPC).
> Sujet de mémoire : *Conception d'un système d'intrusion automatique multi-agent pour l'étude de la résilience des IDS face aux techniques d'évasion basées sur le Machine Learning.*

---

## Aperçu terminal

```ansi
[38;5;46m┌──(nzoyi㉿kali)-[~/Projet-Nzoyi][0m
[38;5;46m└─$[0m python main.py --target 192.168.100.11 --profile stealth

[38;5;46m[*][0m Orchestrator      : pipeline initialisé (7 agents)
[38;5;46m[*][0m Recon Agent       : 3 hôtes actifs détectés sur 192.168.100.0/24
[38;5;46m[*][0m Enumerator Agent  : services fingerprintés (22/tcp, 80/tcp, 5000/tcp)
[38;5;46m[*][0m Vuln Analyzer     : 2 vecteurs exploitables identifiés
[38;5;46m[*][0m Evasion Agent     : Q-table chargée — profil stealth (T2, delay=500ms, frag=on)
[38;5;226m[~][0m Evaluation Agent  : lecture eve.json (Suricata)...
[38;5;46m[+][0m Aucune alerte critique — score de furtivité : 0.92
[38;5;46m[+][0m Rapport généré → results/report_2026-07-21.json
```

---

## Architecture

```
                    ┌──────────────────────────────┐
                    │   PANEL LLM (interchangeable)  │
                    │ Anthropic │ OpenRouter │ Ollama │
                    └───────┬──────────┬──────┬──────┘
                 stratégie  │  triage  │ ordre│ rationale
                            ▼          ▼      ▼          ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ORCHESTRATOR AGENT                          │
│              Coordonne le pipeline de pentest                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
     ┌───────────────────────┼───────────────────────┐
     ▼                       ▼                       ▼
┌─────────┐           ┌─────────────┐         ┌───────────┐
│  RECON  │──────────▶│ ENUMERATOR  │────────▶│   VULN    │◀┄┄ triage LLM
│  Agent  │           │    Agent    │         │  Analyzer │     (réordonne,
└─────────┘           └─────────────┘         └─────┬─────┘      n'invente rien)
                                                    │
                    ┌───────────────────────────────┘
                    ▼
              ┌───────────┐    feedback     ┌─────────────┐
              │  EVASION  │◀───────────────▶│ EVALUATION  │◀┄┄ rationale LLM
              │ Q-Learning│  (100% RL,       │  (Suricata  │    (explique,
              │  jamais   │   zéro LLM)      │   + ML)     │     n'influence
              │  de LLM   │                  └─────────────┘     jamais le verdict)
              └─────┬─────┘
                    │
                    ▼
              ┌───────────┐
              │  ATTACK   │◀┄┄ raffinement LLM (ordre des tentatives,
              │   Agent   │     jamais une cible inventée)
              └───────────┘

         ═══════════ Pentest Tree (PTT) ═══════════
              Mémoire partagée entre tous les agents
```

| Agent | Rôle | Assisté par le panel LLM ? |
|-------|------|------------------------------|
| **Orchestrator** | Pilote le pipeline complet, décide profil/cibles stratégiques | ✅ Plan stratégique |
| **Recon** | Découverte réseau et cartographie des ports | ❌ |
| **Enumerator** | Fingerprinting des services | ❌ |
| **Vulnerability Analyzer** | Identification des failles exploitables + triage de priorité | ✅ Triage (réordonne seulement) |
| **Evasion** | Adaptation des paramètres d'attaque via Q-Learning | ❌ **jamais** — RL pur (H1/H3) |
| **Attack** | Exécution des actions offensives + raffinement de l'ordre | ✅ Raffinement d'ordre (jamais la technique) |
| **Evaluation** | Lecture des logs IDS, fusion Suricata+ML, rationale explicatif | ✅ Rationale seul (zéro influence sur le verdict) |

---

## Pourquoi l'Evasion reste 100% RL

Le cœur scientifique du mémoire (hypothèses **H1** et **H3**) repose sur le
fait que la stratégie d'évasion est **apprise par renforcement**, pas
suggérée par un modèle de langage. Introduire un LLM dans cette boucle
invaliderait la mesure de convergence (H1) et la recherche du seuil de
rupture défensive (H3). C'est pourquoi tout le panel LLM décrit ci-dessous
est **strictement cantonné aux couches stratégique et d'analyse** —
`EvasionAgent` et `EvasionQLearner` n'importent et n'appellent jamais de
backend LLM, à aucun niveau du code.

---

## Environnement de lab

Le projet s'exécute sur un **banc KVM/libvirt** hébergé sur Kali Linux bare-metal — réseau isolé `nzoyi-lab` (192.168.100.0/24), sans egress :

| Machine | Rôle | Réseau | IP |
|---------|------|--------|-----|
| **Kali Linux** (hôte bare-metal) | Attaquant : NZOYI, Nmap, orchestrateur | `nzoyi-lab` | `192.168.100.10` |
| **Ubuntu Server 24.04.4 LTS** (VM) | Défenseur + cible : Suricata 8.0.6, RF Oracle (Flask), SSH, Apache | `enp2s0` → `nzoyi-lab` | `192.168.100.11` |

La VM cible possède une seconde carte (`enp1s0` → réseau NAT `default`) réservée au provisioning. Banc validé le 2026-07-21.

Le guide complet de configuration est dans [`docs/LAB_SETUP.md`](docs/LAB_SETUP.md).

---

## Benchmark IDS multi-modèles

Le détecteur d'anomalie déployé sur la VM cible (`RF Oracle`, port 5000) n'est
plus un unique Random Forest : `benchmark/` entraîne et compare **5 familles
de classifieurs** (Random Forest, XGBoost, MLP, Régression logistique,
k-NN) sur le **même** espace de features, avec un seul pipeline de
prétraitement partagé et fitté uniquement sur le split officiel
`UNSW_NB15_training-set.csv` (jamais recombiné avec le test).

```bash
python -m benchmark.run_benchmark --data-dir data/
# → models/preprocessor.joblib, models/<modèle>.joblib
# → results/benchmark.{json,csv,md}, results/config.json
```

`service/` expose ensuite n'importe lequel de ces modèles via la même API
Flask `/predict` (`{prediction, score}`, port 5000) — le détecteur servi se
choisit avec `NZOYI_IDS_MODEL` (`rf` / `xgboost` / `mlp` / `logreg` / `knn`),
sans changer le reste du pipeline attaquant. C'est le mécanisme qui permet de
tester **H2 — Transférabilité** de l'évasion Q-Learning contre plusieurs
détecteurs. Détails : [`service/README.md`](service/README.md).

---

## Panel LLM multi-fournisseur

NZOYI expose **un seul fournisseur LLM configuré à la fois**, utilisé par
4 couches de décision distinctes — chacune avec son propre prompt, son
schéma de validation, et un **repli déterministe systématique** si le LLM
est désactivé, indisponible, ou renvoie une réponse invalide :

| Couche | Ce qu'elle décide | Ce qu'elle ne décide **jamais** |
|--------|--------------------|-----------------------------------|
| **Stratégique** (`LLMOrchestrator`) | Profil d'attaque, ports/services cibles, lancer ou non la boucle d'évasion | La stratégie d'évasion elle-même (RL pur) |
| **Triage** (`VulnTriageLLM`) | Réordonne les vulnérabilités déjà corrélées par ordre de priorité d'exploitation | N'invente, ne modifie, ne supprime jamais un finding |
| **Raffinement** (`AttackPriorityLLM`) | Affine l'ordre des tentatives d'attaque sur les ports déjà sélectionnés | Ne choisit jamais une technique d'exploitation, ni une cible hors du périmètre découvert |
| **Rationale** (`EvaluationRationaleLLM`) | Génère une explication en langage naturel du verdict IDS déjà calculé | Zéro influence sur `detected` / `detection_rate` (lecture seule, post-hoc) |

### Fournisseurs supportés

Un unique adaptateur générique (`OpenAICompatibleBackend`) sert toute API
Chat Completions compatible OpenAI — changer de fournisseur ne touche
**jamais le code**, seulement la configuration :

| Fournisseur | `NZOYI_LLM_PROVIDER` | Usage |
|-------------|------------------------|-------|
| **Anthropic Claude** | `anthropic` (défaut) | Référence qualité, cloud |
| **OpenRouter** (DeepSeek-R1 et autres) | `openai_compatible` | Accès à des modèles tiers via une seule clé |
| **Ollama (local)** | `openai_compatible` + `base_url=http://localhost:11434/v1` | Modèles **spécialisés cybersécurité** en local, zéro dépendance réseau, comparaison generalist vs. specialized (DeepSeek-R1, Foundation-Sec-8B, WhiteRabbitNeo-2) |

```bash
# .env — cibler Ollama en local
NZOYI_LLM_PROVIDER=openai_compatible
NZOYI_OPENAI_COMPAT_BASE_URL=http://localhost:11434/v1
NZOYI_OPENAI_COMPAT_API_KEY=ollama-local-no-auth
NZOYI_OPENAI_COMPAT_MODEL=deepseek-r1:8b
```

### Choisir un modèle au lancement

```bash
# Surcharge ponctuelle sans toucher à .env
python main.py --target 192.168.100.11 --llm-model deepseek-r1:8b

# Menu interactif listant les modèles Ollama installés localement
python main.py --target 192.168.100.11

# Reproductibilité totale — aucun appel LLM, repli heuristique partout
python main.py --target 192.168.100.11 --no-llm
```

Détails complets des variables d'environnement : [`.env.example`](.env.example).

---

## Démarrage rapide

### Prérequis

- Python 3.11+
- Kali Linux bare-metal avec KVM/QEMU (libvirt)
- VM Ubuntu Server 24.04.4 LTS sur réseau isolé `nzoyi-lab` — Suricata 8.0.6, services cibles (22 / 80 / 5000)

### Installation

```bash
git clone https://github.com/14juanito/Projet-Nzoyi.git
cd Projet-Nzoyi

python3 -m venv ~/nzoyi-env
source ~/nzoyi-env/bin/activate
pip install -r requirements.txt
```

### Tests de validation

```bash
python main.py --test
```

Résultat attendu (extrait — 72 tests au total, backends LLM toujours mockés,
aucun appel réseau réel dans la suite) :

```
  [PASS] PTT shared memory
  [PASS] Q-Learning update cycle
  [PASS] Orchestrator 7-agent pipeline
  [PASS] Stealth profile configuration
  [PASS] Panel LLM — VulnTriage backend valide : réordonne sans perte
  [PASS] Panel LLM — AttackPriority sanitize : ports hors périmètre filtrés
  [PASS] Panel LLM — EvaluationRationale LLMBackendError → chaîne vide
  ...
  ══════════════════════════════════════════════════
    Test Results
  ══════════════════════════════════════════════════
  │  Passed                    72/72
  │  Status                    ALL PASS ✓
  ══════════════════════════════════════════════════
```

### Premier lancement

```bash
# Simulation (sans trafic réseau)
python main.py --target 192.168.100.11 --profile stealth --dry-run

# Contre la cible du lab
python main.py --target 192.168.100.11 --profile stealth

# Avec feedback Suricata (eve.json)
python main.py --target 192.168.100.11 --profile stealth --eve-log /var/log/suricata/eve.json
```

### Profils d'attaque

| Profil | Timing Nmap | Délai | Fragmentation | Usage |
|--------|-------------|-------|---------------|-------|
| `stealth` | T2 | 500 ms | Oui | Évasion IDS (recommandé) |
| `default` | T3 | 0 ms | Non | Scan standard |
| `aggressive` | T4 | 0 ms | Non | Baseline comparaison |

---

## Structure du projet

```
Projet-Nzoyi/
├── assets/
│   └── openzoyi-logo.png       # Logo du projet
├── benchmark/                  # Benchmark IDS multi-modèles (UNSW-NB15)
│   ├── data.py                 # Chargement split officiel, retrait fuites
│   ├── preprocessing.py        # ColumnTransformer partagé (fit train only)
│   ├── models.py               # Factory des 5 classifieurs
│   ├── metrics.py               # Métriques + timing d'inférence
│   ├── report.py                # Sérialisation JSON/CSV/Markdown
│   └── run_benchmark.py        # CLI d'entraînement/évaluation
├── service/                    # API Flask IDS-ML (déployée cible, port 5000)
│   └── app.py                  # NZOYI_IDS_MODEL sélectionne le détecteur
├── docs/
│   └── LAB_SETUP.md            # Configuration lab KVM/libvirt
├── nzoyi/
│   ├── agents/                 # 7 agents spécialisés
│   ├── core/                   # PTT, profils d'attaque
│   ├── llm/                    # Panel LLM (J1-J6)
│   │   ├── backend.py           # Contrat LLMBackend (ABC)
│   │   ├── backend_resolver.py  # Résolution partagée du fournisseur configuré
│   │   ├── backends/            # AnthropicBackend, OpenAICompatibleBackend
│   │   ├── orchestrator_llm.py  # Couche stratégique
│   │   ├── vuln_triage_llm.py   # Couche triage vulnérabilités
│   │   ├── attack_priority_llm.py       # Couche raffinement d'ordre d'attaque
│   │   └── evaluation_rationale_llm.py  # Couche rationale explicatif
│   └── rl/                     # Q-Learning (Evasion Agent) — jamais de LLM ici
├── tests/
│   └── test_validation.py      # 72 tests de validation
├── main.py                     # Point d'entrée CLI (--llm-model, menu Ollama)
└── requirements.txt
```

---

## Hypothèses de recherche

| Hypothèse | Énoncé |
|-----------|--------|
| **H1 — Convergence** | Le Q-Learning converge vers une stratégie d'évasion stable en un nombre fini de cycles |
| **H2 — Transferabilité** | Les stratégies apprises sur Suricata sont partiellement transférables à d'autres IDS |
| **H3 — Limite défensive** | Il existe un seuil de rupture où l'évasion rend l'attaque aussi lente qu'un pentest manuel |

---

## Journal des évolutions

| Étape | Contenu | Statut |
|-------|---------|--------|
| **J1** | Abstraction `LLMBackend` + `AnthropicBackend` — gestion d'erreur sécurisée (jamais de détail d'exception propagé) | ✅ Mergé |
| **J2** | `OpenAICompatibleBackend` générique (`base_url` paramétrable) — sert OpenRouter, Ollama, et de futurs fournisseurs sans changement de code | ✅ Mergé |
| **J3/J4** | Panel de modèles locaux via Ollama (CPU) pour comparer un modèle généraliste à des modèles spécialisés cybersécurité (DeepSeek-R1-8B, Foundation-Sec-8B, WhiteRabbitNeo-2-8B) + flag `--llm-model` et menu interactif | 🔄 En cours (contraintes disque/RAM/bande passante sur l'environnement local) |
| **J5/J6** | Extraction `resolve_backend()` partagée + câblage du panel sur VulnAnalyzer (triage), Attack (raffinement d'ordre) et Evaluation (rationale explicatif) — 72/72 tests, zéro régression sur la boucle Q-Learning | ✅ Mergé |
| **J7** | Comparatif empirique du panel (Claude vs OpenRouter vs modèles locaux) sur le même scénario de lab | ⏳ À venir |

Chaque étape a été relue indépendamment (diff complet + re-exécution de la
suite de tests) avant merge — voir l'historique des commits pour le détail.

---

## Avertissement légal

Ce projet est destiné **exclusivement** à la recherche académique et aux tests de pénétration **autorisés** sur un réseau **isolé** que vous contrôlez.

Ne jamais utiliser NZOYI contre des systèmes sans autorisation explicite. L'auteur décline toute responsabilité en cas d'usage illégal.

---

## Auteur

**Jean El-rohi Mukendi**  
Faculté des Sciences Informatiques — Université Protestante au Congo

---

<p align="center">
  <sub>OpenZoyi v0.1.0 — Multi-agent automated intrusion system</sub>
</p>

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:00ff41,100:0d1117&height=120&section=footer" alt="footer" width="100%">
</p>