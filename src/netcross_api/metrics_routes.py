# SPDX-License-Identifier: GPL-3.0-or-later
"""Dernier relevé publié, borné et exposé sous l'authentification de l'API."""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Response

from netcross_core.live_report import LiveReportWriter
from netcross_core.logging_config import get_logger
from netcross_report.metrics_export import (
    Sample,
    collect_live_samples,
    collect_samples,
    redact_samples,
    render_openmetrics,
    render_prometheus_text,
)

logger = get_logger(__name__)


class LatestMetrics:
    """Un seul tuple immuable de séries, jamais l'historique des relevés."""

    def __init__(self) -> None:
        logger.debug("LatestMetrics.__init__: entrée")
        self._lock = threading.Lock()
        self._samples: tuple[Sample, ...] = ()
        logger.debug("LatestMetrics.__init__: fin")

    def replace(self, samples: list[Sample], redactor: Any = None) -> None:
        logger.debug("LatestMetrics.replace: entrée")
        if redactor is not None:
            samples = redact_samples(samples, redactor)
        with self._lock:
            self._samples = tuple(samples)
        logger.debug("LatestMetrics.replace: fin")

    def samples(self) -> tuple[Sample, ...]:
        logger.debug("LatestMetrics.samples: entrée")
        with self._lock:
            result = self._samples
        logger.debug("LatestMetrics.samples: retour {} série(s)", len(result))
        return result

    def report(self, entry: dict, run: str) -> None:
        """Remplace les compteurs directs par les vraies métriques finales."""
        logger.debug("LatestMetrics.report: entrée")
        from netcross_core.redact import AddressRedactor

        redactor = AddressRedactor() if entry.get("redaction_map") is not None else None
        self.replace(collect_samples(entry["report_obj"], run, entry["findings"]), redactor)
        logger.debug("LatestMetrics.report: fin")


class MetricsReportWriter(LiveReportWriter):
    """Publie les compteurs en mémoire même si le disque devient indisponible."""

    def __init__(
        self,
        directory: str | Path,
        render_html: Callable[[dict, list[dict], float], str] | None,
        interval: float,
        metrics: LatestMetrics,
        run: str,
        redact: bool = False,
    ) -> None:
        logger.debug("MetricsReportWriter.__init__: entrée")
        from netcross_core.redact import AddressRedactor

        super().__init__(directory, render_html, interval)
        self._metrics = metrics
        self._run = run
        self._redactor = AddressRedactor() if redact else None
        logger.debug("MetricsReportWriter.__init__: fin")

    def publish(self, snapshot: dict, journal: dict) -> None:
        logger.debug("MetricsReportWriter.publish: entrée")
        self._metrics.replace(collect_live_samples(snapshot, self._run), self._redactor)
        super().publish(snapshot, journal)
        logger.debug("MetricsReportWriter.publish: fin")


def register(app: FastAPI, verify: Callable[..., None], latest: LatestMetrics) -> None:
    logger.debug("metrics_routes.register: entrée")

    @app.get(
        "/metrics",
        tags=["metrics"],
        dependencies=[Depends(verify)],
        response_class=Response,
        responses={
            200: {
                "description": "Dernier relevé publié, éventuellement vide",
                "content": {
                    "text/plain": {"schema": {"type": "string"}},
                    "application/openmetrics-text": {"schema": {"type": "string"}},
                },
            },
            401: {"description": "Clé API absente ou incorrecte"},
        },
    )
    def metrics(format: Literal["prometheus", "openmetrics"] = "prometheus") -> Response:
        """Dernier relevé direct ou analyse finale, sans lancer de capture."""
        logger.debug("metrics: entrée")
        samples = latest.samples()
        if format == "openmetrics":
            content = render_openmetrics(samples)
            media_type = "application/openmetrics-text; version=1.0.0; charset=utf-8"
        else:
            content = render_prometheus_text(samples)
            media_type = "text/plain; version=0.0.4; charset=utf-8"
        logger.debug("metrics: retour Response")
        return Response(content, media_type=media_type, headers={"Cache-Control": "no-store"})

    logger.debug("metrics_routes.register: fin")
