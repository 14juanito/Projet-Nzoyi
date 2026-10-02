# Service IDS-ML (API Flask, port 5000)

Sert n'importe lequel des 5 modèles du benchmark (`benchmark/`) derrière le
même contrat HTTP `/predict` que l'ancien détecteur RF, pour des campagnes de
transférabilité de l'évasion Q-Learning (voir `docs/LAB_SETUP.md` pour la
topologie du lab — ce service tourne sur la VM cible `192.168.100.11`).

## Déploiement

1. Copier `benchmark/`, `service/`, `models/*.joblib` sur la VM cible.
2. `pip install -r service/requirements.txt`
3. Choisir le modèle servi via `NZOYI_IDS_MODEL` (alias reconnus dans
   `benchmark.models.MODEL_ALIASES` : `rf`, `xgboost`, `mlp`, `logreg`, `knn`).

```bash
NZOYI_IDS_MODEL=rf gunicorn --bind 0.0.0.0:5000 "service.app:create_app()"
# ou, pour du développement :
NZOYI_IDS_MODEL=xgboost python -m service.app
```

## Contrat `/predict` (inchangé, compatible `nzoyi.tools.rf_client.RFClient`)

```
POST /predict
Content-Type: application/json

{"dur": 0.05, "spkts": 8, ..., "proto": "tcp", "service": "-", "state": "FIN"}

→ 200 {"prediction": 0, "score": 0.03, "model": "random_forest"}
→ 400 {"error": "Colonnes manquantes", "missing": [...]}
→ 400 {"error": "Colonnes inattendues", "unexpected": [...]}
```

`GET /health` → `{"status": "ok", "model": "<nom_canonique>"}`.

## Changer de détecteur pour une campagne de transférabilité

```bash
export NZOYI_IDS_MODEL=mlp   # ou xgboost / logreg / knn / rf
# redémarrer le service — aucun autre composant (nzoyi, RL) ne change.
```
