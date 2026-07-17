"""Shared helpers for psutil-based collectors (process, network)."""

from __future__ import annotations

import hashlib
import os
import stat
from typing import Callable, TypeVar

import psutil

_HASH_CHUNK_SIZE = 1024 * 1024

T = TypeVar("T")


def safe_psutil_call(fn: Callable[[], T], default: T) -> T:
    """Call a psutil.Process accessor, degrading to `default` on permission
    or race errors instead of crashing (spec §11)."""
    try:
        return fn()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return default


def is_safe_to_read(path: str) -> bool:
    """True only for a regular file (not a symlink target resolved to one
    is fine; what we reject is FIFOs, sockets, and device files). A FIFO
    with no writer on the other end blocks open() forever -- and several
    watched paths (e.g. ~/.ssh/authorized_keys) are user-writable, so
    anyone running as the monitored user could `mkfifo` one of them and
    freeze the collector indefinitely with no privilege needed. Always
    check this before opening a path this module doesn't control."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return False


def hash_file(path: str) -> str | None:
    """SHA-256 of a file's contents, or None if unreadable or not a
    regular file (spec §11: degrade gracefully -- record sha256=null --
    rather than crash or hang; see is_safe_to_read)."""
    if not is_safe_to_read(path):
        return None
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(_HASH_CHUNK_SIZE), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


class HashCache:
    """Caches sha256 by (path, mtime, size): if a file's mtime and size
    haven't changed since it was last hashed, the cached digest is reused
    instead of re-reading the file. On a typical system many processes
    share the same interpreter/binary (e.g. one Python or Chrome build
    backing dozens of processes), so this collapses what would otherwise
    be hundreds of redundant full-file reads per cycle down to one per
    unique binary.

    Deliberately NOT used by the file_integrity collector: that collector
    watches a small, fixed list (~20 paths) where the cost of always
    re-hashing is trivial, and rule 6's whole job is detecting a hash
    change -- trusting mtime+size as a proxy for "unchanged" would let a
    timestomping attacker (modify a file, then reset its mtime) evade
    detection.

    IMPORTANT: the caller MUST call clear() once per collection cycle
    (engine/pipeline.py's run_cycle() does this when given a hash_cache).
    Process/network collectors' hashes feed rule 1's "have I seen this
    (exe_path, sha256) before" baseline check, so cache freshness is NOT
    a security-irrelevant convenience -- an earlier version of this class
    claimed otherwise, which was wrong: without a per-cycle clear, an
    attacker who replaces a binary in place while preserving its mtime and
    size (ordinary timestomping, no special privilege beyond write access
    to that path) would get the OLD cached hash reported forever, so rule
    1 would never fire for the swap and process_observations would record
    a hash that doesn't match what's actually on disk. Clearing once per
    cycle still collapses the redundant hashing *within* a cycle (the
    actual bulk of the win -- see git history/PR notes) while bounding the
    staleness window to "within one snapshot interval," the same
    inherent, already-documented sampling limitation every snapshot-mode
    collector has (spec §5).
    """

    def __init__(self):
        self._cache: dict[str, tuple[float, int, str]] = {}

    def clear(self) -> None:
        self._cache.clear()

    def get(self, path: str) -> str | None:
        try:
            st = os.stat(path)
        except OSError:
            return None

        cached = self._cache.get(path)
        if cached is not None and cached[0] == st.st_mtime and cached[1] == st.st_size:
            return cached[2]

        digest = hash_file(path)
        if digest is not None:
            self._cache[path] = (st.st_mtime, st.st_size, digest)
        return digest
