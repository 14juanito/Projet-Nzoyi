"""Service Flask exposant un détecteur IDS-ML substituable (port 5000).

Ce package est déployé sur la VM cible/défenseur du banc de lab (voir
``docs/LAB_SETUP.md``), séparément du toolkit attaquant ``nzoyi``. Il ne
partage aucun code avec ``nzoyi`` — seul le contrat HTTP ``/predict``
(``{prediction, score}``) les relie, via ``nzoyi.tools.rf_client.RFClient``.
"""

from __future__ import annotations
