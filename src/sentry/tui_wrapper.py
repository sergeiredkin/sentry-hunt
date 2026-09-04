"""Wrapper for 'sentry tui' that auto-elevates to sudo if needed."""

import os
import sys
import subprocess


def main():
    """Launch sentry tui with automatic sudo elevation.

    If not running as root, re-executes with sudo using the Python module
    invocation to avoid PATH issues. If already root, runs directly.
    """
    if os.geteuid() == 0:
        # Already running as root, execute directly
        from sentry.cli import main as cli_main
        sys.argv = ["sentry", "tui"]
        cli_main()
    else:
        # Not root, re-execute with sudo using Python module invocation
        # This ensures sudo can find sentry even if PATH is sanitized
        result = subprocess.run(
            [sys.executable, "-m", "sentry.cli", "tui"],
            check=False,
        )
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
