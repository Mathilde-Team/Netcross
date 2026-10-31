# SPDX-License-Identifier: GPL-3.0-or-later
"""Fake sklearn module injected into sys.modules for coverage of the
ML-dependent code paths (anomaly.py, flow_classifier.py) when scikit-learn
is not installed in the test environment.

The real sklearn is never exercised here -- only the netcross_ai glue
code around it (BaselineError on too-small baseline, MIN_SAMPLES check,
FlowPrediction/FlowAnomaly dataclasses, _explain). A fake model whose
predict/score_samples return deterministic values is enough to drive
every branch.
"""

from __future__ import annotations


class _FakeIsolationForest:
    def __init__(self, n_estimators=100, contamination="auto", random_state=0):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state

    def fit(self, X):  # noqa: N803 -- convention scikit-learn
        self._n = len(X)
        return self

    def score_samples(self, X):  # noqa: N803 -- convention scikit-learn
        # score_samples: more negative = more anomalous (sklearn convention).
        # First sample is anomalous.
        return [-0.6 if i == 0 else 0.3 for i in range(len(X))]

    def predict(self, X):  # noqa: N803 -- convention scikit-learn
        # -1 = anomaly, 1 = normal. First sample flagged.
        return [-1 if i == 0 else 1 for i in range(len(X))]


class _FakeRandomForestClassifier:
    def __init__(self, n_estimators=100, random_state=0, class_weight=None):
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.class_weight = class_weight

    def fit(self, X, y):  # noqa: N803 -- convention scikit-learn
        self._classes = sorted(set(y))
        self.classes_ = self._classes
        return self

    def predict_proba(self, X):  # noqa: N803 -- convention scikit-learn
        out = []
        for i in range(len(X)):
            row = [0.1] * len(self._classes)
            # first class gets high probability for first sample, second for rest
            idx = 0 if i == 0 else min(1, len(self._classes) - 1)
            row[idx] = 0.9
            out.append(row)
        return out


class _Ensemble:
    IsolationForest = _FakeIsolationForest
    RandomForestClassifier = _FakeRandomForestClassifier


class _Sklearn:
    ensemble = _Ensemble


def install():
    import sys

    sys.modules["sklearn"] = _Sklearn()
    sys.modules["sklearn.ensemble"] = _Ensemble()


def uninstall():
    import sys

    sys.modules.pop("sklearn", None)
    sys.modules.pop("sklearn.ensemble", None)
