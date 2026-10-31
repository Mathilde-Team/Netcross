#!/usr/bin/env python3
"""scripts/bench_datasets.py -- jeux pcapng multi-points déterministes (issue #1015).

Mince enveloppe autour de :func:`netcross_core.testing.synth.main` ; toute la
logique (et sa couverture de tests) est dans le module. Exemples :

    python3 scripts/bench_datasets.py --sortie /tmp/jeu --points 3 --paquets 100000 \\
        --segment-perte 2 --taux-perte 0.01 --graine 7
    python3 scripts/bench_datasets.py --sortie /tmp/banc --matrice

Voir docs/quality/jeux-synthetiques.md.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from netcross_core.testing.synth import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
