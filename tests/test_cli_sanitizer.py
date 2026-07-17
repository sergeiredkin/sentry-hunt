from __future__ import annotations

from sentry.cli import _sanitize_for_terminal


def test_sanitize_leaves_normal_text_unchanged():
    assert _sanitize_for_terminal("New executable observed: /usr/bin/bash") == (
        "New executable observed: /usr/bin/bash"
    )


def test_sanitize_strips_escape_byte():
    # A filename can legally contain a raw ESC byte on Linux (only NUL and
    # '/' are forbidden) -- this is the terminal-injection finding from the
    # security review: printing it unsanitized would inject a real
    # terminal control sequence into the console.
    malicious = "New executable observed: /tmp/\x1b[2K\rFAKE: all clear"
    result = _sanitize_for_terminal(malicious)
    assert "\x1b" not in result
    assert "\r" not in result


def test_sanitize_strips_newline_to_prevent_fake_extra_lines():
    malicious = "New executable observed: /tmp/x\n  [HIGH] R2 fake unrelated alert"
    result = _sanitize_for_terminal(malicious)
    assert "\n" not in result


def test_sanitize_strips_all_c0_control_chars_and_del():
    s = "".join(chr(c) for c in range(0x00, 0x20)) + "\x7f" + "safe text"
    result = _sanitize_for_terminal(s)
    assert result == "safe text"
