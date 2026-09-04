"""Allow running sentry as a module: python -m sentry <command>"""

from sentry.cli import main

if __name__ == "__main__":
    main()
