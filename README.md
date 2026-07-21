<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:00ff41,100:0d1117&height=200&section=header&text=OpenZoyi&fontSize=64&fontAlignY=38&fontColor=39FF14&animation=fadeIn&desc=Multi-Agent%20Adaptive%20Intrusion%20Framework&descAlignY=58&descSize=17&descColor=39FF14" alt="OpenZoyi banner" width="100%">
</p>

<p align="center">
  <img src="assets/openzoyi-logo.png" alt="OpenZoyi — Multi-agent automated intrusion system" width="200">
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&duration=2800&pause=900&color=39FF14&center=true&vCenter=true&width=700&lines=%5B*%5D+Initialisation+du+Pentest+Tree+(PTT)...;%5B*%5D+Chargement+de+7+agents+sp%C3%A9cialis%C3%A9s...;%5B*%5D+Evasion+Agent+%E2%80%94+Q-Learning+actif...;%5B*%5D+Analyse+des+alertes+Suricata+(eve.json)...;%5B%2B%5D+Syst%C3%A8me+multi-agents+op%C3%A9rationnel." alt="Typing SVG">
</p>

<p align="center">
  <strong>Système multi-agents d'intrusion automatisée avec évasion adaptative des IDS</strong>
</p>

<p align="center">
  <a href="https://github.com/14juanito/Projet-Nzoyi"><img src="https://img.shields.io/badge/version-0.1.0-39FF14?style=flat-square&labelColor=0d1117" alt="Version"></a>
  <a href="https://github.com/14juanito/Projet-Nzoyi"><img src="https://img.shields.io/badge/python-3.11+-39FF14?style=flat-square&logo=python&logoColor=39FF14&labelColor=0d1117" alt="Python"></a>
  <a href="docs/LAB_SETUP.md"><img src="https://img.shields.io/badge/lab-isol%C3%A9-39FF14?style=flat-square&labelColor=0d1117" alt="Lab isolé"></a>
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
- un **Evasion Agent** basé sur le **Q-Learning** qui optimise timing, fragmentation et discrétion des scans,
- un **Evaluation Agent** qui lit le feedback des alertes IDS (Suricata `eve.json`).

> Projet de fin de cycle — Faculté des Sciences Informatiques, Université Protestante au Congo (UPC).

---

## Aperçu terminal

```ansi
[38;5;46m┌──(nzoyi㉿kali)-[~/Projet-Nzoyi][0m
[38;5;46m└─$[0m python main.py --target 192.168.100.11 --profile stealth

[38;5;46m[*][0m Orchestrator      : pipeline initialisé (7 agents)
[38;5;46m[*][0m Recon Agent       : 3 hôtes actifs détectés sur 192.168.100.0/24
[38;5;46m[*][0m Enumerator Agent  : services fingerprintés (22/tcp, 80/tcp, 443/tcp)
[38;5;46m[*][0m Vuln Analyzer     : 2 vecteurs exploitables identifiés
[38;5;46m[*][0m Evasion Agent     : Q-table chargée — profil stealth (T2, delay=500ms, frag=on)
[38;5;226m[~][0m Evaluation Agent  : lecture eve.json (Suricata)...
[38;5;46m[+][0m Aucune alerte critique — score de furtivité : 0.92
[38;5;46m[+][0m Rapport généré → results/report_2026-07-21.json
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     ORCHESTRATOR AGENT                          │
│              Coordonne le pipeline de pentest                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
     ┌───────────────────────┼───────────────────────┐
     ▼                       ▼                       ▼
┌─────────┐           ┌─────────────┐         ┌───────────┐
│  RECON  │──────────▶│ ENUMERATOR  │────────▶│   VULN    │
│  Agent  │           │    Agent    │         │  Analyzer │
└─────────┘           └─────────────┘         └─────┬─────┘
                                                    │
                    ┌───────────────────────────────┘
                    ▼
              ┌───────────┐    feedback     ┌─────────────┐
              │  EVASION  │◀───────────────▶│ EVALUATION  │
              │ Q-Learning│                 │  (Suricata) │
              └─────┬─────┘                 └─────────────┘
                    │
                    ▼
              ┌───────────┐
              │  ATTACK   │
              │   Agent   │
              └───────────┘

         ═══════════ Pentest Tree (PTT) ═══════════
              Mémoire partagée entre tous les agents
```

| Agent | Rôle |
|-------|------|
| **Orchestrator** | Pilote le pipeline complet |
| **Recon** | Découverte réseau et cartographie des ports |
| **Enumerator** | Fingerprinting des services |
| **Vulnerability Analyzer** | Identification des failles exploitables |
| **Evasion** | Adaptation des paramètres d'attaque via Q-Learning |
| **Attack** | Exécution des actions offensives |
| **Evaluation** | Lecture des logs IDS et mesure de détection |

---

## Environnement de lab

Le projet est conçu pour un **réseau isolé** à deux machines :

| Machine | Rôle | IP |
|---------|------|-----|
| **PC 1 — Kali Linux** | Attaquant : NZOYI, Ollama, Nmap | `192.168.100.10` |
| **PC 2 — Ubuntu Server 22.04** | Défenseur + cible : Suricata, SSH, Apache, FTP | `192.168.100.11` |

Le guide complet d'installation pas à pas est disponible dans [`docs/LAB_SETUP.md`](docs/LAB_SETUP.md).

---

## Démarrage rapide

### Prérequis

- Python 3.11+
- Kali Linux (PC attaquant)
- Ubuntu Server 22.04 + Suricata (PC cible, réseau isolé)

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

Résultat attendu :

```
NZOYI validation tests
========================================
  [PASS] PTT shared memory
  [PASS] Q-Learning update cycle
  [PASS] Orchestrator 7-agent pipeline
  [PASS] Stealth profile configuration
========================================
Result: 4/4 tests passed
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
├── docs/
│   └── LAB_SETUP.md            # Guide d'installation du lab
├── nzoyi/
│   ├── agents/                 # 7 agents spécialisés
│   ├── core/                   # PTT, profils d'attaque
│   └── rl/                     # Q-Learning (Evasion Agent)
├── tests/
│   └── test_validation.py      # 4 tests de validation
├── main.py                     # Point d'entrée CLI
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
