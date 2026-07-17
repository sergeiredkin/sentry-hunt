# Sentry

Sentry watches a Linux computer for changes and tells you what changed, so you can decide if it is dangerous.

## What it does

Sentry takes a snapshot of your computer every minute: what programs are running, what network ports are open, who has an account, and more. It compares each new snapshot to the one before it. When something new or different shows up, Sentry checks it against a small set of security rules. If a rule matches, Sentry creates an alert with the evidence, so you can look at it and decide what to do.

Sentry runs only on your own computer. It does not send any data to the internet or to any other service. It only *reads* information from your system. It never changes, deletes, or fixes anything on its own.

## What it watches

- Programs that are running
- Network ports that are listening for connections
- User accounts and permission changes (for example, someone getting admin rights)
- Things that start automatically when the computer boots
- Changes to important system files (like the password file or SSH settings)
- Failed login attempts

## Quick start

You need Python 3.11 or newer.

```bash
pip install -e .
```

Run a few collection cycles and print any findings to your terminal:

```bash
sentry run --cycles 2
```

Or launch the interactive dashboard, which keeps collecting in the background and shows alerts in a live table:

```bash
sentry tui
```

The first time you run either command, Sentry creates its own database automatically. You do not need to set anything up by hand.

## Why it needs extra permissions

Some checks need to read files or process details that a normal user cannot see. For example, the file that stores password hashes, or the process list of other users. Sentry works fine without extra permission, but it will see less.

If you want Sentry to see everything, run it with `sudo`. Either way, Sentry only *reads* these files. It never writes to them or changes them. When it cannot read something, it just records that fact and moves on, instead of stopping.

## Current limitations

This is an early, working version. A few things to know:

- New installs may show alerts for normal things at first. The feature that waits before alerting on brand-new setups is not fully connected yet.
- You have to start Sentry yourself. It does not yet run on its own in the background as a system service.
- It has been tested on Debian, Ubuntu, Fedora, and Rocky Linux.

## What it will not do

- It does not scan for viruses or malware signatures.
- It does not capture or inspect network traffic.
- It has no graphical window. It runs in your terminal.
- It watches one computer at a time. It does not manage a fleet of machines.

## Project layout

- `src/sentry/` — the application code
- `tests/` — the test suite
- `docs/DESIGN.md` — the original design notes, written for an AI coding assistant during development. Read it if you want the full technical detail (data model, rules, architecture).

## Running the tests

```bash
pip install -e ".[dev]"
pytest
```

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
