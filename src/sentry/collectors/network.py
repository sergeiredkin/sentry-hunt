"""Push-shaped network collector (spec §3, §12).

Snapshot mode: the engine calls collect(sink) on a timer; each call
enumerates LISTEN and ESTABLISHED inet sockets and emits one
NetworkObservation per socket. Owning-process fields (exe_path/sha256/user)
are best-effort: psutil cannot resolve them for sockets owned by another
user without elevated privileges, and that's recorded as None rather than
treated as an error (spec §11).
"""

from __future__ import annotations

import socket

import psutil

from sentry.collectors._common import HashCache, safe_psutil_call as _safe
from sentry.engine.observations import NetworkObservation
from sentry.engine.sink import ObservationSink

_TCP_STATUSES_OF_INTEREST = frozenset({psutil.CONN_LISTEN, psutil.CONN_ESTABLISHED})


class NetworkCollector:
    name = "network"
    respects_warmup = True  # rule 3 (new listening port) is warmup-respecting per spec §7

    def __init__(self, hash_cache: HashCache | None = None):
        # Sharing one HashCache with ProcessCollector means a listener's
        # owning binary is often already hashed for free this cycle.
        self._hash_cache = hash_cache if hash_cache is not None else HashCache()

    def collect(self, sink: ObservationSink) -> None:
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Degrade gracefully (spec §11): nothing collected this cycle
            # rather than crashing the engine.
            return

        for conn in connections:
            if conn.laddr is None or not conn.laddr:
                continue  # unbound socket, nothing to report

            protocol = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
            if protocol == "tcp" and conn.status not in _TCP_STATUSES_OF_INTEREST:
                # Skip transient states (TIME_WAIT, CLOSE_WAIT, SYN_SENT, ...)
                # -- rule 3 only cares about LISTEN, and ESTABLISHED is kept
                # as evidence for rule 1's "concurrent connections" field.
                continue

            laddr_ip, laddr_port = conn.laddr
            raddr_ip, raddr_port = conn.raddr if conn.raddr else ("", 0)

            exe_path: str | None = None
            user: str | None = None
            if conn.pid is not None:
                try:
                    proc = psutil.Process(conn.pid)
                    exe_path = _safe(proc.exe, None) or None
                    user = _safe(proc.username, None)
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    pass

            sha256 = self._hash_cache.get(exe_path) if exe_path else None

            sink.emit(
                NetworkObservation(
                    protocol=protocol,
                    laddr=laddr_ip,
                    lport=laddr_port,
                    raddr=raddr_ip,
                    rport=raddr_port,
                    status=conn.status,
                    pid=conn.pid,
                    exe_path=exe_path,
                    sha256=sha256,
                    user=user,
                )
            )
