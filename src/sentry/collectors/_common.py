"""Shared helpers for psutil-based collectors (process, network)."""

from __future__ import annotations

import hashlib
import os
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


def hash_file(path: str) -> str | None:
    """SHA-256 of a file's contents, or None if unreadable (spec §11:
    degrade gracefully -- record sha256=null -- rather than crash)."""
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
    unique binary -- and, since the cache is instance-scoped and reused
    across collect() calls by the caller, down to effectively zero on
    cycles where nothing changed.

    Deliberately NOT used by the file_integrity collector: that collector
    watches a small, fixed list (~20 paths) where the cost of always
    re-hashing is trivial, and rule 6's whole job is detecting a hash
    change -- trusting mtime+size as a proxy for "unchanged" would let a
    timestomping attacker (modify a file, then reset its mtime) evade
    detection. This cache exists purely for process/network collectors'
    evidence hashing, where no security property depends on freshness.
    """

    def __init__(self):
        self._cache: dict[str, tuple[float, int, str]] = {}

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
