"""Push-shaped process collector (spec §3, §12).

Snapshot mode: the engine calls collect(sink) on a timer; each call
enumerates the live process table and emits one ProcessObservation per
process into the sink. The collector never returns state -- see
collectors/base.py's Collector protocol.
"""

from __future__ import annotations

import psutil

from sentry.collectors._common import HashCache, safe_psutil_call as _safe
from sentry.engine.observations import ProcessObservation
from sentry.engine.sink import ObservationSink


class ProcessCollector:
    name = "process"
    respects_warmup = True  # rule 1 (new executable) is warmup-respecting per spec §7

    def __init__(self, hash_cache: HashCache | None = None):
        # Defaults to a private cache if the caller doesn't share one, but
        # passing one in (e.g. shared with NetworkCollector, and reused
        # across cycles) is what actually collapses redundant hashing --
        # see HashCache's docstring.
        self._hash_cache = hash_cache if hash_cache is not None else HashCache()

    def collect(self, sink: ObservationSink) -> None:
        for pid in psutil.pids():
            try:
                proc = psutil.Process(pid)
                ppid = proc.ppid()
                create_time = proc.create_time()
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                # Exited between listing and inspection -- simply not
                # observed this cycle; close_cycle() will close it if it
                # was previously open.
                continue

            exe_path = _safe(proc.exe, None) or None
            cmdline_parts = _safe(proc.cmdline, [])
            user = _safe(proc.username, None)
            sha256 = self._hash_cache.get(exe_path) if exe_path else None

            sink.emit(
                ProcessObservation(
                    pid=pid,
                    ppid=ppid,
                    exe_path=exe_path,
                    sha256=sha256,
                    cmdline=" ".join(cmdline_parts),
                    user=user,
                    create_time=create_time,
                )
            )
