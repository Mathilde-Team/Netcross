# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_ai -- module IA/ML **optionnel et local** (issue #146, FLOW-5).

Trois usages, tous executes sur la machine de traitement (aucune API cloud) :

1. ``anomaly`` : detection d'anomalies de flux par rapport a une baseline de
   trafic normal (Isolation Forest, scikit-learn) ;
2. ``flow_classifier`` : classification de flux (normal / tunnel / C2 /
   exfiltration / obfusque...) avec score de confiance, entraine sur un jeu
   etiquete par l'analyste (foret aleatoire, scikit-learn) ;
3. ``report_writer`` : resume executif en francais, correlations et
   recommandations -- gabarit deterministe sans aucune dependance, ou modele
   de langage local (ollama, llama.cpp) joint **uniquement en boucle locale**.

Partage (issue #271) : ``model_pack`` (paquets ZIP anonymes et verifies de
baselines/exemples) et ``outbox`` (boite d'envoi hors connexion, tickets
« modeles ») -- CLI ``src/netcross_ai_models_cli.py``.

Installation : ``pip install "netcross[ai]"`` ou ``uv sync --extra ai``.
Sans scikit-learn, le reste de Netcross fonctionne normalement ; seules les
options ``--ai-anomalies``/``--ai-classify`` le signalent (voir ``optional``).
"""

from netcross_ai.features import FEATURE_NAMES, flow_features
from netcross_ai.optional import AIUnavailableError, ml_available, require_ml
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

__all__ = ["FEATURE_NAMES", "AIUnavailableError", "flow_features", "ml_available", "require_ml"]
