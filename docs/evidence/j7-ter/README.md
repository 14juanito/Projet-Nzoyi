# Preuves brutes — campagne J7-ter (n=20, correctif target_signature)

Suite directe de J7 (`docs/evidence/j7/README.md`) après le correctif commité
en `97dc910` (branche `feat/j7-llm-panel-comparison`) : le plan stratégique
LLM influence désormais réellement `EvasionAgent` via `target_signature`
(hash CRC32 de l'ordre des ports priorisés par le triage). Objectif de ce
run : vérifier si le taux de détection diverge enfin de façon exploitable
statistiquement, à `n=20` cycles/backend (au lieu de 8), maintenant que le
lien fonctionne.

Cible **inchangée** : `192.168.100.14` (déjà enrichie à 4 CVE — vsftpd
2.3.4/CVE-2011-2523, Apache 2.4.49/CVE-2021-41773+CVE-2021-42013,
SSH/CVE-2023-38408), connectivité et services vérifiés actifs avant la
campagne. OpenRouter reste hors scope (décision actée en J7, clé API
connue non fonctionnelle) — marqué `absent` explicitement, jamais testé.

6 backends : les 5 Ollama locaux de J7 + `claude` (`claude-sonnet-5`).
Méthodologie identique à J7 : découverte dynamique du panel
(`discover_panel()`), smoke test avant chaque backend, campagne réelle
entrelacée juste après (modèle encore chaud), tout fallback/anomalie
loggé avec horodatage, jamais exclu silencieusement.

## Vérification préalable (point 3 de la tâche) — seed plan-dépendante confirmée

Avant la campagne complète, le premier backend terminé (WhiteRabbitNeo-2.5
-Qwen-7B) a été utilisé pour confirmer que `target_signature` n'est plus
figé à `0` (valeur systématique de J7, où `LearningRunner` n'appliquait
jamais le plan) : `target_signature` cycle 1 = `2907638143`. Confirmé
non-nul sur les 6 backends (voir tableau ci-dessous) — le correctif est
bien actif pour cette campagne.

## Résultats — tableau comparatif (n=20)

| Modèle | Statut | Durée | Détection (n=20) | Fallback triage | Fallback rationale | target_signature |
|---|---|---|---|---|---|---|
| claude (claude-sonnet-5) | ✅ | 146.7s | 5.0% (1/20) | **1/1** (anomalie, voir ci-dessous) | 0/20 | 31136374 |
| WhiteRabbitNeo-2.5-Qwen-7B | ✅ | 1316.5s | 0.0% (0/20) | 0/1 | 0/20 | 2907638143 |
| Dolphin3.0-8B | ✅ | 674.4s | 0.0% (0/20) | 0/1 | 0/20 | 901141454 |
| Lily-Cybersecurity-7B | ✅ | 987.9s | **15.0% (3/20)** | 0/1 | 3/20 | 31136374 |
| WhiteRabbitNeo-2-8B | ✅ | 1815.5s | 0.0% (0/20) | 1/1 (échec total, connu) | 20/20 (échec total, connu) | 31136374 |
| Foundation-Sec-8B-Instruct | ✅ | 1734.6s | 0.0% (0/20) | 0/1 | 0/20 | 2907638143 |
| openrouter | ⬜ absent (hors scope) | — | — | — | — | — |

## ⚠️ Correction — l'« anomalie » Claude n'était pas un hiccup d'API

**Rapport initial erroné, corrigé après vérification approfondie (voir
section « Vérifications complémentaires » ci-dessous) : le fallback du
triage Claude n'est PAS un incident transitoire de l'API.** C'est un bug
de parsing reproductible : `nzoyi/llm/{orchestrator,vuln_triage,attack_priority,
evaluation_rationale}_llm.py` appellent tous `json.loads(text)` directement
sur le texte brut du backend, **sans jamais retirer les fences markdown**
(` ```json ... ``` `) que Claude (et d'autres modèles) utilisent
systématiquement pour envelopper leur JSON. `json.loads` sur un texte qui
commence par `` ```json `` lève immédiatement `Expecting value: line 1
column 1 (char 0)` — exactement l'erreur observée. Ce n'est pas spécifique
à ce run : voir la section dédiée plus bas pour l'ampleur réelle du
problème (il affecte aussi le rôle stratégique, pas que le triage).

## Finding clé — même signature ⇒ même trafic, mais PAS même détection

Vérification directe sur les PTT (`docs/evidence/j7-ter/ptt/*.ptt.json`) :
les 6 backends se répartissent en **3 groupes selon `target_signature`**,
et à l'intérieur de chaque groupe, **la séquence complète des 20 actions
`evasion_step` est strictement identique** (confirmé octet pour octet) :

| target_signature | Backends | Séquence d'actions identique ? |
|---|---|---|
| `2907638143` | WhiteRabbitNeo-2.5-Qwen-7B, Foundation-Sec-8B-Instruct | ✅ identique |
| `901141454` | Dolphin3.0-8B (seul dans son groupe) | — |
| `31136374` | Lily-Cybersecurity-7B, WhiteRabbitNeo-2-8B, claude | ✅ identique |

**C'est exactement le comportement attendu du correctif** : le trafic ne
dépend plus seulement du numéro de cycle (comme en J7, un seul groupe pour
les 6 backends) mais de l'ordre de triage — deux backends qui triagent
dans le même ordre (ou qui y retombent via le même repli déterministe)
envoient désormais, à juste titre, un trafic identique.

**Mais, à l'intérieur du groupe `31136374` (trafic rigoureusement
identique pour les 3 backends), les cycles réellement détectés par
Suricata diffèrent** : Lily → cycles `[5, 10, 15]` (3 détections),
WhiteRabbitNeo-2-8B → aucune, claude → cycle `[2]` (1 détection). **Même
stimulus réseau, résultats de détection différents.** Cela confirme ce que
l'analyse de clusterisation de J7 avait déjà montré à un niveau plus
grossier : une part significative de la variance de détection observée
vient du comportement réel, non-déterministe, de la cible/Suricata face à
un trafic réseau réel (cadence temporelle réelle très différente entre
backends — claude termine 20 cycles en 146.7s, les backends Ollama locaux
en 674–1816s, donc l'espacement temporel réel entre scans successifs
diffère radicalement même pour un stimulus « identique » au sens de la
séquence d'actions) — **pas uniquement de l'ordre de triage**, même après
correctif.

## Comparaison explicite J7 (n=8, trafic identique) vs J7-ter (n=20, trafic divergent)

| | J7 (avant correctif) | J7-ter (après correctif) |
|---|---|---|
| Trafic réseau entre backends | **identique** (1 seul groupe de séquence d'actions, pour les 6) | **divergent par groupe de triage** (3 groupes distincts sur 6 backends) |
| Cycles | 8/backend | 20/backend |
| Détection la plus différenciée | 12.5% (1/8) pour 4/6 backends — indistinguable | **Lily-Cybersecurity-7B se détache : 15.0% (3/20)**, seul backend avec un triage réellement réussi ET un groupe de signature propre à lui en pratique (bien que partagé avec 2 autres via coïncidence/repli) |
| Preuve empirique du correctif | — | ✅ 3 groupes de trafic distincts confirmés sur les PTT (vs 1 groupe unique en J7) |
| Limite résiduelle | seed indépendante du plan (bug) | trafic dépend du plan, mais **la détection réelle reste dominée par le bruit d'exécution réseau/IDS**, pas uniquement par le stimulus — même 3 backends à trafic identique ont des résultats de détection différents |

**Conclusion** : le correctif a un effet réel et mesurable sur le *trafic*
(preuve directe, pas une affirmation) — la seed n'est plus indépendante du
plan stratégique, et des backends qui triagent différemment envoient
désormais des stimuli différents. En revanche, la *détection* ne diverge
toujours pas de façon propre et attribuable à la qualité du LLM : même à
`n=20`, et même entre 3 backends à trafic rigoureusement identique, le
résultat de détection Suricata varie — la cadence temporelle réelle de la
campagne (dominée par la latence du backend LLM, pas par le contenu de sa
décision) semble être un facteur de confusion au moins aussi important que
l'ordre de triage lui-même. Un futur run contrôlant pour la durée totale
de campagne (ex. en forçant un délai fixe entre cycles, indépendant de la
latence LLM) serait nécessaire pour isoler proprement l'effet du plan
stratégique de celui de la cadence réseau.

## Contenu de ce dossier

| Fichier/dossier | Contenu |
|---|---|
| `smoke_test_<label>.json` | Smoke test par backend (6 fichiers), avant chaque campagne réelle. |
| `ptt/<label>.ptt.json` | PTT complet de chaque run réel (6 fichiers), 20 cycles chacun. |
| `../../../results/j7_ter_llm_panel_comparison.{json,csv,md}` | Rapports agrégés, avec colonne `target_signature` (moyenne/distincts) absente de J7. |

Aucun artefact J7 original (`docs/evidence/j7/`, `results/j7_llm_panel_comparison.*`) n'a été modifié ou écrasé par cette campagne.

## Vérifications complémentaires (post-hoc, lecture seule des PTT/eve.json)

### Vérification 1 — Identité de trafic confirmée pour TOUS les groupes, pas seulement A

Vérifié directement (pas supposé) : dans le Groupe B
(`target_signature=2907638143`), la séquence complète des 20
`evasion_step` **et** des 20 `attack_plan` (timing/scan_delay_ms/fragment,
hors timestamp) est strictement identique octet pour octet entre
WhiteRabbitNeo-2.5-Qwen-7B et Foundation-Sec-8B-Instruct. Pas d'anomalie
de calcul de signature détectée sur ce groupe — même conclusion que pour
le Groupe A (déjà vérifié dans le corps du rapport ci-dessus).

### Vérification 2 — Les 4 backends à 0% : deux cas bien distincts, à ne pas mélanger

**PTT** : pour les 4 backends (WhiteRabbitNeo-2.5-Qwen-7B,
Foundation-Sec-8B-Instruct, Dolphin3.0-8B, WhiteRabbitNeo-2-8B), les 20
nœuds `ids_feedback` sont tous présents (aucun cycle silencieusement
sauté), `detected == false` et `alert_count == 0` sur l'intégralité des
20 cycles pour les 4, et le recon a bien vu les mêmes 3 ports (`21, 22,
80`) que les autres runs. Jusqu'ici, rien d'anormal en apparence.

**Mais le mirror `eve.json` brut raconte une autre histoire pour 2 des 4
backends.** En cherchant, dans la fenêtre temporelle exacte de chaque
run, des alertes **non-bruit** (hors `SURICATA Ethertype unknown`) avec
`src_ip=192.168.100.10` (notre attaquant) → `dst_ip=192.168.100.14` (la
cible) :

- **WhiteRabbitNeo-2.5-Qwen-7B et Dolphin3.0-8B** : **zéro** alerte
  non-bruit dans toute la fenêtre de leur run. Le 0% reflète une absence
  réelle de signature déclenchée — **pas de problème de mesure détecté**.
- **WhiteRabbitNeo-2-8B et Foundation-Sec-8B-Instruct** : le mirror
  contient bel et bien des alertes réelles et pertinentes pendant leur
  fenêtre de run — `ET SCAN Potential SSH Scan`, `ET SCAN Nmap Scripting
  Engine User-Agent Detected`, `ET INFO Apache HTTP Server 2.4.49
  Observed - Vulnerable to CVE-2021-41773`, plusieurs `ET SCAN Suspicious
  inbound to <mySQL/Oracle/PostgreSQL/MSSQL/VNC>` — avec les bons
  src/dst IP, dans des bursts temporellement situés **à l'intérieur de la
  fenêtre nominale d'un cycle précis** (vérifié pour WhiteRabbitNeo-2-8B :
  alertes à `19:43:06-15`, `19:56:38-46` et `20:02:49`, tombant
  respectivement dans les fenêtres des cycles 2, 13 et 19) — **et
  pourtant `alert_count=0` est enregistré pour CES cycles précis dans le
  PTT.**

  **Conclusion : pour ces 2 backends, le 0% n'est PAS une preuve fiable
  d'évasion réussie — c'est (au moins en partie) un problème de mesure.**
  Hypothèse la plus plausible (non confirmée formellement, nécessiterait
  d'instrumenter le délai de relais SSH pour trancher) : le volume très
  élevé de bruit décodeur sur ces deux fenêtres (627 et 2004 événements
  `SURICATA Ethertype unknown` respectivement, contre 241 et 3065 pour
  les 2 autres — mais sur une durée de run 2 à 3× plus longue) sature le
  tunnel SSH `tail -F` qui miroite `eve.json` depuis la VM, introduisant
  un retard de livraison des lignes suffisant pour qu'une alerte générée
  par le cycle *N* n'arrive sur le fichier local qu'**après** la lecture
  du cycle *N* ET après le `baseline_ids()` (qui avance le curseur) du
  cycle *N+1* — la faisant tomber dans l'angle mort entre deux lectures,
  jamais comptée par aucun cycle. **Ne pas interpréter le 0% de ces deux
  backends spécifiquement comme une évasion réussie dans le mémoire** —
  le signal mesuré est cassé, pas le phénomène réel.

### Vérification 3 — L'accord du Groupe A : ni coïncidence de raisonnement, ni ordre « évident »

Investigation plus poussée que prévu : `target_signature` provient de
`plan["ports_cibles"]` du **rôle stratégique** (`LLMOrchestrator`,
nœuds PTT `llm_strategy`/`llm_replan`/`llm_decision`), **pas** du rôle
triage (`VulnTriageLLM`) dont j'avais initialement supposé l'influence —
erreur de ma part dans l'analyse précédente, corrigée ici. Les deux rôles
sont des instances LLM indépendantes avec leurs propres succès/échecs.

Pour les 3 membres du Groupe A, le nœud `llm_raw_response` (réponse brute
du rôle stratégique) montre que **les trois ont bien produit une réponse
réelle et distincte** — ce n'est donc ni une coïncidence de raisonnement,
ni un repli immédiat :

- **claude** : JSON valide et cohérent (`ports_cibles: [22,80,443,445,3389]`,
  raisonnement détaillé), mais enveloppé en fences `` ```json ``` `` →
  échoue au parsing (bug décrit ci-dessus) → repli déterministe.
- **WhiteRabbitNeo-2-8B** : JSON enveloppé en fences ET tronqué/invalide
  (`"ports_cibles": [22]` puis un second essai avec une fence mal fermée
  `` ``}`` ``) → échoue pour DEUX raisons cumulées (fences + malformation
  réelle) → repli déterministe.
- **Lily-Cybersecurity-7B** : réponse NON fenced mais **littéralement un
  gabarit non rempli** — `"profil": "stealth|default|aggressive"`
  (les 3 choix séparés par `|`, jamais résolus en un seul), fautes de
  frappe sur les clés (`services_focu`, `lancer_boucle_evaision`) → échec
  de schéma réel, indépendant du bug de fences → repli déterministe.

**Réponse à la question posée** : la convergence du Groupe A vers le même
`target_signature` est **un artefact du repli déterministe partagé**
(`ports_cibles=[22,80,21]`, dérivé des ports recon triés par défaut), PAS
un accord de raisonnement entre modèles, et PAS non plus un ordre
« évident » qu'un raisonnement réel aurait spontanément produit — les
3 raisonnements réels récupérés ci-dessus sont tous DIFFÉRENTS de ce
repli et DIFFÉRENTS entre eux. Les 3 backends ont échoué pour 3 raisons
distinctes (fences seules, fences + contenu invalide, gabarit non rempli)
qui convergent par coïncidence vers le MÊME code de repli, pas vers le
même raisonnement.

### Vérification 4 — Timing réel sur les 6 backends

Espacement réel entre `ids_feedback` consécutifs (pas la durée totale) :

| Backend | Groupe | Espacement moyen (s) | Variance (s²) | Écart-type (s) | Cycles détectés |
|---|---|---|---|---|---|
| claude | A | 6.27 | 4.2 | 2.04 | [2] |
| Lily-Cybersecurity-7B | A | 29.07 | **191.9** | **13.85** | **[5, 10, 15]** |
| WhiteRabbitNeo-2-8B | A | 72.41 | 1.8 | 1.36 | [] |
| WhiteRabbitNeo-2.5-Qwen-7B | B | 52.75 | 2.8 | 1.68 | [] |
| Foundation-Sec-8B-Instruct | B | 73.58 | 3.2 | 1.79 | [] |
| Dolphin3.0-8B | C | 20.22 | 0.2 | 0.42 | [] |

Dolphin3.0 (Groupe C, seul, espacement moyen 20.22s, variance quasi nulle
0.2) ne ressemble, en magnitude d'espacement, à aucun backend des Groupes
A/B — le plus proche en moyenne est Lily (29.07s) mais avec une variance
~1000× plus élevée. **Pas de profil de timing partagé identifiable entre
Dolphin3.0 et un backend précis des deux autres groupes.**

**Pattern observé sur l'ensemble du panel (à interpréter avec prudence,
n=6, pas une preuve statistique)** : le seul backend avec des détections
multiples (Lily, 3/20) a aussi, de très loin, la variance d'espacement la
plus élevée (191.9 vs < 4.2 pour tous les autres). Les 4 backends à 0%
détection ont tous une variance d'espacement faible (< 3.2). Claude a une
variance faible (4.2) mais 1 détection — donc le pattern n'est pas
parfaitement net (claude est une exception partielle). Hypothèse
plausible mais **non confirmée** : une cadence irrégulière entre cycles
(donc entre stimuli réseau) augmenterait la probabilité de franchir des
seuils de détection Suricata sensibles à des fenêtres temporelles — mais
avec seulement 6 points de données et 1 seule exception notable, ceci
reste une piste à tester sur un futur run avec plus de backends/cycles,
pas une conclusion à affirmer comme établie.

## Recommandation — ce qu'on peut honnêtement affirmer dans le mémoire

**Peut être affirmé avec preuve directe** :
1. Le correctif `target_signature` fonctionne mécaniquement : des
   backends qui aboutissent au même plan stratégique (réel ou de repli)
   envoient un trafic réseau identique ; des plans différents envoient
   des trafics différents. Vérifié sur les 3 groupes, pas seulement un.
2. Un bug de parsing réel et non spécifique à un backend (fences markdown
   jamais retirées avant `json.loads`, dans les 4 rôles LLM) fait
   échouer silencieusement des réponses LLM par ailleurs valides et
   cohérentes — y compris chez Claude. C'est un bug corrigible,
   actuellement non corrigé (hors périmètre de cette vérification).
3. Pour 2 des 6 backends (WhiteRabbitNeo-2-8B, Foundation-Sec-8B-Instruct),
   le 0% de détection rapporté n'est pas fiable : des alertes IDS réelles
   et pertinentes existent dans la fenêtre de leur run mais n'ont été
   comptées par aucun cycle — probable angle mort de mesure (latence du
   relais SSH), pas une évasion démontrée.

**Ne peut PAS être honnêtement affirmé avec les données actuelles** :
- Que le panel LLM a un effet démontré sur la détection réelle : même à
  trafic rigoureusement identique (Groupe A), les résultats de détection
  diffèrent ; et pour 2 backends, le chiffre de détection lui-même n'est
  pas fiable.
- Qu'un modèle est "meilleur en évasion" qu'un autre sur la base de ces
  chiffres de détection — la variance observée est dominée par des
  facteurs de mesure/timing non contrôlés, pas par le contenu des
  décisions LLM.
- Une corrélation établie entre variance de timing et détection — piste
  intéressante (Lily), mais n=6 et une exception partielle (claude) ne
  permettent pas de la présenter comme un résultat, seulement comme une
  piste de travail future.

**Recommandation concrète** : avant de pouvoir conclure quoi que ce soit
sur l'effet du panel LLM sur la détection, corriger (1) le bug de parsing
des fences markdown (gain potentiel : beaucoup plus de plans réellement
LLM-pilotés au lieu de replis coïncidents) et (2) fiabiliser la capture
IDS (mirror SSH local avec timestamp d'arrivée explicite, ou lecture
directe sur la VM plutôt que relayée) avant de rejouer une campagne dont
les chiffres de détection seraient attribuables avec confiance au panel
LLM plutôt qu'à des artefacts d'infrastructure.

## ⚠️⚠️ Correction majeure — les « détections fantômes » n'en étaient pas

**Investigation complémentaire (mini-run ciblé claude + Lily, instrumentation
`eval_debug` activée) : la cause des 4 "détections fantômes" (claude cycle
2 ; Lily cycles 5/10/15) a été trouvée, et ce n'est NI un bug NZOYI NI un
problème de curseur/relais SSH — c'est un décalage d'horloge entre la VM
cible et le poste Kali.**

Confirmé en direct :
```
Kali (local, orchestrateur) : ven. 09 oct. 2026 22:33:04 UTC
VM cible (192.168.100.14)    : ven. 09 oct. 2026 23:11:21 UTC
```
**La VM cible a ~38 minutes d'avance sur l'horloge du poste qui orchestre
la campagne.** Vérifié par lecture directe des octets exacts du mirror
(positions de curseur capturées par l'instrumentation `eval_debug`,
immunisées par construction à tout décalage d'horloge) : l'alerte
`ET SCAN Potential SSH Scan` comptée au cycle 2 de claude est arrivée
**physiquement** dans la fenêtre de lecture de ce cycle (curseur avant
45866495, après 45868147, lecture à 22:30:29 locale) — une alerte bien
réelle, générée par le trafic réel de ce cycle — mais son horodatage
**interne** (horloge Suricata sur la VM) affiche `23:08:45`, soit ~38 min
après l'horodatage local de la lecture qui l'a comptée.

**Ce que ça invalide, et ce que ça ne touche pas** :
- **La mesure live (`detected`/`alert_count`) n'a jamais été fausse.**
  `SuricataLogReader.get_recent_alerts(..., since_cursor_only=True)`
  compte par **position de curseur**, jamais par l'horodatage embarqué —
  immunisé par construction contre ce décalage. Les 4 "fantômes" étaient
  de vraies détections, correctement comptées, juste mal expliquées par
  mon diagnostic post-hoc.
- **Mon outil de diagnostic post-hoc (`ids_reconciliation.py`, et les
  vérifications manuelles des sections précédentes de ce document) EST
  affecté** : il réattribue par **horodatage embarqué** (horloge VM)
  comparé à des fenêtres de cycle construites avec l'**horloge locale**
  (PTT, `datetime.now()` sur le poste Kali) — sans jamais soupçonner un
  décalage de 38 minutes entre les deux. C'est une erreur de méthode de
  ma part, pas un bug du framework NZOYI.
- **Conséquence directe : le chiffre « 19 et 9 alertes perdues » pour
  WhiteRabbitNeo-2-8B et Foundation-Sec-8B-Instruct, trouvé avec cette
  même méthode (horodatage embarqué vs fenêtres locales), doit être
  traité comme NON CONFIRMÉ** — ni validé, ni invalidé, simplement
  obtenu avec un outil qui a le même angle mort. Il faudrait le
  revérifier par position d'octet (comme fait ici pour claude/Lily, via
  `eval_debug`) pour trancher, ce qui nécessite soit un nouveau run
  instrumenté soit une correction du décalage mesuré dans
  `ids_reconciliation.py` — non fait à ce stade.

**Pas de correctif de code NZOYI nécessaire** : la logique de détection
en direct était correcte. Le point à corriger, si on veut refaire ce genre
de diagnostic proprement, est opérationnel (synchroniser l'horloge de la
VM via NTP/chrony avant toute future campagne) et/ou méthodologique
(faire reposer toute réconciliation post-hoc sur les positions de curseur
de `eval_debug`, jamais sur l'horodatage embarqué, qui s'est révélé non
fiable pour comparer deux machines).

## Synchronisation d'horloge — correctif appliqué (2026-10-09, ~23:44 UTC)

**Correction du diagnostic initial** : l'hypothèse "VM cible non
synchronisée NTP" était fausse. Vérification directe (`timedatectl
status` sur les deux machines) :

- **VM cible (192.168.100.14)** : `System clock synchronized: yes`, NTP
  actif (`systemd-timesyncd`), synchronisée avec `ntp.ubuntu.com` depuis
  le matin (13:02:48 UTC) — **déjà correcte, jamais le problème**.
- **Poste Kali (hôte orchestrateur)** : `System clock synchronized: no`,
  `systemd-timesyncd` **désactivé**. C'est cette machine qui dérivait —
  c'est elle qui explique le décalage (~38 min la veille au soir, ~20-25s
  au moment de la vérification, car une horloge non synchronisée dérive
  de façon non prévisible, parfois corrigée brutalement par l'hyperviseur
  ou une resynchronisation manuelle plutôt que progressivement).

**Correctif appliqué sur le poste Kali** (pas sur la VM, qui n'avait rien
à corriger) :
```
sudo systemctl enable --now systemd-timesyncd
sudo timedatectl set-ntp true
```
Vérifié après coup : `System clock synchronized: yes`, `NTP service:
active`. Décalage mesuré avec la cible via `check_clock_skew()`
(`run_j7_campaign.py`) : **0.27s** (bien sous le seuil de 5s) — contre
~24.7s quelques minutes avant ce correctif, et ~38 min la veille.

**Implication pour tout futur run** : le garde-fou (`--clock-check-ssh-key`)
devrait désormais rapporter un écart négligeable. Les chiffres de
détection de WhiteRabbitNeo-2-8B et Foundation-Sec-8B-Instruct (TÂCHE 5,
re-run propre) peuvent être collectés en confiance, sans dépendre d'une
réconciliation post-hoc par horodatage.
