from __future__ import annotations

import hashlib
import os
import threading

from sentry.collectors._common import HashCache, hash_file, is_safe_to_read


def test_get_computes_hash_first_time(tmp_path):
    f = tmp_path / "bin"
    f.write_bytes(b"hello")

    cache = HashCache()
    assert cache.get(str(f)) == hashlib.sha256(b"hello").hexdigest()


def test_get_returns_cached_value_without_rereading(tmp_path, monkeypatch):
    f = tmp_path / "bin"
    f.write_bytes(b"hello")

    call_count = 0
    real_hash_file = __import__("sentry.collectors._common", fromlist=["hash_file"]).hash_file

    def counting_hash_file(path):
        nonlocal call_count
        call_count += 1
        return real_hash_file(path)

    monkeypatch.setattr("sentry.collectors._common.hash_file", counting_hash_file)

    cache = HashCache()
    cache.get(str(f))
    cache.get(str(f))
    cache.get(str(f))

    assert call_count == 1


def test_get_rehashes_when_mtime_changes(tmp_path):
    f = tmp_path / "bin"
    f.write_bytes(b"version1")
    cache = HashCache()
    first = cache.get(str(f))

    f.write_bytes(b"version2 (different length)")
    os.utime(f, (0, 12345))  # force a different mtime
    second = cache.get(str(f))

    assert first != second
    assert second == hashlib.sha256(b"version2 (different length)").hexdigest()


def test_get_rehashes_when_size_changes_even_if_mtime_forced_equal(tmp_path):
    f = tmp_path / "bin"
    f.write_bytes(b"short")
    cache = HashCache()
    os.utime(f, (0, 1000))
    first = cache.get(str(f))

    f.write_bytes(b"a much longer replacement payload")
    os.utime(f, (0, 1000))  # same forced mtime, different size
    second = cache.get(str(f))

    assert first != second


def test_get_returns_none_for_missing_path(tmp_path):
    missing = tmp_path / "does-not-exist"
    cache = HashCache()
    assert cache.get(str(missing)) is None


def test_shared_cache_across_two_lookups_of_same_path(tmp_path):
    f = tmp_path / "python3.11"
    f.write_bytes(b"fake interpreter binary")
    cache = HashCache()

    # simulate ProcessCollector and NetworkCollector both hashing the same
    # binary within one cycle
    digest_a = cache.get(str(f))
    digest_b = cache.get(str(f))
    assert digest_a == digest_b == hashlib.sha256(b"fake interpreter binary").hexdigest()


def test_clear_forces_rehash_even_if_mtime_size_unchanged(tmp_path, monkeypatch):
    f = tmp_path / "bin"
    f.write_bytes(b"hello")
    cache = HashCache()
    cache.get(str(f))

    call_count = 0
    real_hash_file = __import__("sentry.collectors._common", fromlist=["hash_file"]).hash_file

    def counting_hash_file(path):
        nonlocal call_count
        call_count += 1
        return real_hash_file(path)

    monkeypatch.setattr("sentry.collectors._common.hash_file", counting_hash_file)

    cache.clear()
    cache.get(str(f))  # same mtime/size as before, but cache was cleared

    assert call_count == 1


def test_clear_on_empty_cache_is_a_noop():
    cache = HashCache()
    cache.clear()  # must not raise


# --- is_safe_to_read / FIFO-hang guard (the fix for the security review's
# "a monitored file can freeze the tool forever" finding) -------------------


def test_is_safe_to_read_true_for_regular_file(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"x")
    assert is_safe_to_read(str(f)) is True


def test_is_safe_to_read_false_for_missing_path(tmp_path):
    assert is_safe_to_read(str(tmp_path / "missing")) is False


def test_is_safe_to_read_false_for_fifo(tmp_path):
    fifo_path = tmp_path / "evil_fifo"
    os.mkfifo(fifo_path)
    assert is_safe_to_read(str(fifo_path)) is False


def test_hash_file_returns_none_for_fifo_without_hanging(tmp_path):
    """The core regression test: a FIFO with no writer must not block
    open() forever. Runs the risky call on a daemon thread with a timeout
    so a real regression fails this test fast instead of hanging the
    whole suite."""
    fifo_path = tmp_path / "evil_fifo"
    os.mkfifo(fifo_path)

    result: dict[str, object] = {}

    def call():
        result["value"] = hash_file(str(fifo_path))

    t = threading.Thread(target=call, daemon=True)
    t.start()
    t.join(timeout=5)

    assert not t.is_alive(), "hash_file blocked on a FIFO instead of skipping it"
    assert result["value"] is None


def test_hash_cache_get_returns_none_for_fifo_without_hanging(tmp_path):
    fifo_path = tmp_path / "evil_fifo"
    os.mkfifo(fifo_path)
    cache = HashCache()

    result: dict[str, object] = {}

    def call():
        result["value"] = cache.get(str(fifo_path))

    t = threading.Thread(target=call, daemon=True)
    t.start()
    t.join(timeout=5)

    assert not t.is_alive(), "HashCache.get blocked on a FIFO instead of skipping it"
    assert result["value"] is None
