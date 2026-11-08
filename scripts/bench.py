#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""scripts/bench.py -- banc de performance de Netcross (issue #1017, chantier #994).

Mince enveloppe autour de :func:`netcross_core.testing.bench.main` ; toute la
logique (et sa couverture de tests) est dans le module. Exemples :

    python3 scripts/bench.py --mini --json /tmp/banc.json
    python3 scripts/bench_datasets.py --sortie /tmp/jeux --matrice
    python3 scripts/bench.py --jeux /tmp/jeux --parallel 1,2,4,8 --repetitions 3 \\
        --json banc.json --markdown banc.md

``scripts/bench_memory.py`` (#283) reste la courbe mémoire du seul pipeline
Python sur des objets ``Pkt`` synthétiques ; ce banc-ci mesure l'analyse
complète (tshark compris) sur de vrais fichiers pcapng.
Voir docs/quality/banc-performance.md.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from netcross_core.testing.bench import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
