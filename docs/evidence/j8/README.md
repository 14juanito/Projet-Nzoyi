# Preuves brutes — campagne comparative J8 (Suricata+RF vs Zeek+ML)

Ce dossier conserve les artefacts bruts de la campagne décrite dans
`results/j8_zeek_ml_vs_suricata_rf.md` (non versionné, `results/` est
gitignored). Récupérés depuis le scratchpad de la session après coup, sur
demande explicite de conservation — aucune nouvelle exécution n'a été lancée
pour produire ces fichiers.

## Réponse à la question « contamination exclue ? »

**Oui, exclue, avec preuve temporelle sans ambiguïté :**

- Redémarrage propre de `nzoyi-zeekml.service` sur la VM zeek-ml-target :
  **03:08:49 UTC** (`journalctl -u nzoyi-zeekml.service` :
  `Stopping ... Deactivated successfully ... Started`).
- Les 3 runs Zeek+ML dont les chiffres (62.5% / 100% / 100%) figurent dans le
  rapport final ont démarré et fini **après** ce redémarrage, d'après les
  `mtime` des fichiers `summaries/zeek_ml_*.summary.json` eux-mêmes écrits par
  le script au moment de l'exécution :
  - `zeek_ml_stealth.summary.json` → 03:09:25 UTC
  - `zeek_ml_default.summary.json` → 03:09:39 UTC
  - `zeek_ml_aggressive.summary.json` → 03:09:54 UTC
- Chaque run appelle `EvaluationAgent.baseline_ids()` → `seek_end()` sur le
  fichier mirroré **au tout début de son propre run** (3-4ème ligne de
  `run_j8_campaign.py::run_one`) : par construction, aucune ligne antérieure
  à cet instant ne peut compter comme « nouvelle » pour ce run, quel que soit
  le contenu accumulé avant.
- Les répertoires du **premier passage** (contaminé, figé depuis
  02:59:41 UTC jusqu'au redémarrage) ont été supprimés
  (`rm -rf j8_runs/zeek_ml_*`) **avant** de relancer — il n'y a donc aucun
  chevauchement possible entre les deux jeux de données.
- Seule trace du premier passage contaminé :
  `summaries/all_summaries.FIRST_PASS_CONTAMINATED.json`, qui montre bien
  `final_detection_rate: 0.0` pour les 3 profils Zeek+ML de ce passage —
  **ce fichier n'a jamais servi à calculer les pourcentages du rapport final**
  (le générateur de rapport relit individuellement chaque
  `summaries/<backend>_<profile>.summary.json`, pas ce fichier agrégé stale).

Voir `anomalies_log_excerpt_incident_and_recovery.txt` lignes 1–16 (activité
normale puis silence à partir de 02:59:41) et lignes 17–18 (`Started CONN
Monitoring Process` à 03:08:50, immédiatement après le redémarrage) pour la
preuve côté log applicatif brut.

## Contenu de ce dossier

| Fichier/dossier | Contenu | Origine / horodatage |
|---|---|---|
| `ptt/<backend>_<profile>.ptt.json` | PTT complet (arbre d'évaluation détaillé : signatures, `rf_proba`, `alert_count` par cycle) d'un run — **6 fichiers**, un par (backend × profil), car l'architecture NZOYI instancie un `PentestTree` neuf par run. Il n'existe pas de PTT unique fusionnant les 48 cycles. | Écrits sur disque par `OrchestratorAgent._write_ptt_state()` pendant l'exécution réelle (post-redémarrage pour les 3 `zeek_ml_*`). |
| `summaries/<backend>_<profile>.summary.json` | Résumé par run (cycles, `final_detection_rate`, `convergence` cycle-par-cycle, `duration_s`, ports recon) — 6 fichiers, écrits par `run_j8_campaign.py` lui-même. | Idem. |
| `summaries/all_summaries.FIRST_PASS_CONTAMINATED.json` | Agrégat du **premier passage complet** (6 runs), généré avant la découverte de l'incident KitNET — montre `0.0` pour les 3 profils Zeek+ML. Conservé comme preuve de la contamination, **explicitement exclu du rapport final**. | Premier passage, ~04:02 (horodatage machine, voir mtime du fichier). |
| `campaign_stdout_first_pass_contaminated.txt` | stdout brut du premier passage complet (6 runs), tel qu'écrit par `nohup python3 run_j8_campaign.py > campaign.log` à l'époque. Montre le faux 0% Zeek+ML in situ. | Premier passage. |
| `campaign_stdout_second_pass_reconstructed.txt` | stdout du second passage (3 runs Zeek+ML, post-redémarrage) — **reconstruit depuis la transcription de session, pas un fichier écrit en temps réel sur disque** (voir en-tête du fichier). La preuve faisant foi pour ce passage reste les `summary.json`/`ptt.json` correspondants, horodatés par le système de fichiers. | Second passage, voir disclaimer dans le fichier. |
| `anomalies_log_excerpt_incident_and_recovery.txt` | Extrait brut (60 premières lignes) du mirror local de `anomalies.log` (AutoZeekWatch) : activité normale (02:58:48–02:59:41), silence (incident), reprise à 03:08:50, puis début du second passage valide (scores 0.51–1.53 pour le profil stealth, scores massifs ~8.6e16 pour le balayage multi-ports default/aggressive déclenché par l'agent d'attaque). | Mirror SSH temps réel (`tail -F` côté Kali) du fichier distant `/var/log/nzoyi/anomalies.log` sur zeek-ml-target. |

## Ce qui n'a pas pu être conservé

- Le fichier `anomalies.log` complet côté VM a été écrasé (`logging.FileHandler`
  en mode `'w'`) à chaque redémarrage du service — seul le mirror local
  (tail -F continu côté Kali, jamais interrompu pendant la session) a conservé
  l'historique complet ; l'extrait ci-dessus en est un sous-ensemble représentatif,
  pas le fichier intégral (667 Ko / 3095+ lignes à la fin de la session, incluant
  du bruit multicast post-campagne sans rapport avec les cycles mesurés).
- Le stdout du second passage Zeek+ML n'a pas été redirigé vers un fichier au
  moment de l'exécution (voir ci-dessus) — reconstruit honnêtement, pas fabriqué
  a posteriori comme s'il s'agissait d'un fichier contemporain.
