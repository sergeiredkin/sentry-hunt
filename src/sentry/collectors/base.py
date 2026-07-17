from __future__ import annotations

from typing import Protocol

from sentry.engine.sink import ObservationSink


class Collector(Protocol):
    """Push-shaped collector interface (spec §3).

    Snapshot mode: the engine calls collect(sink) on a timer.
    Continuous mode (future): a collector calls sink.emit(...) on each OS
    event. Same sink, same downstream — collectors never return state.
    """

    name: str
    respects_warmup: bool

    def collect(self, sink: ObservationSink) -> None: ...
