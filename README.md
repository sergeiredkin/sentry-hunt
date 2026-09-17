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

## Install

Requires Python 3.11 or newer.

**Recommended: from GitHub**

```bash
pip install git+https://github.com/sergeiredkin/sentry-hunt.git
```

**For development:**

```bash
git clone https://github.com/sergeiredkin/sentry-hunt.git
cd sentry-hunt
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Configuration

Sentry uses a 60-second snapshot interval and a 7-day warmup by default. Optional configuration can be placed at `~/.config/sentry/config.toml`:

```toml
[sentry]
snapshot_interval_seconds = 60
warmup_days = 7
auth_per_account_threshold = 5
auth_total_threshold = 10
auth_window_minutes = 10
journal_lookback_minutes = 15
```

Environment variables such as `SENTRY_SNAPSHOT_INTERVAL_SECONDS` override TOML values. `SENTRY_CONFIG_PATH` selects another config file, and `SENTRY_CRITICAL_PATHS` accepts a colon-separated critical-file list.

## Quick start

**Launch the interactive dashboard** (automatically elevates to sudo):

```bash
sentry-tui
```

(You will be prompted for your password the first time. Sentry needs elevated privileges to see all system changes.)

**Or run collection cycles from the command line:**

```bash
sentry run --cycles 2
```

The first time you run either command, Sentry creates its own database automatically. You do not need to set anything up by hand.

## Why it needs extra permissions

Some checks need to read files or process details that a normal user cannot see. For example, the file that stores password hashes, or the process list of other users. Sentry works fine without extra permission, but it will see less.

If you want Sentry to see everything, run it with `sudo`. Either way, Sentry only *reads* these files. It never writes to them or changes them. When it cannot read something, it just records that fact and moves on, instead of stopping.

## Troubleshooting

**`sentry-tui` asks for password every time**

If you want to skip the password prompt, add Sentry to your sudoers file (passwordless sudo):

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: $(which sentry)" | sudo tee -a /etc/sudoers.d/sentry
sudo chmod 440 /etc/sudoers.d/sentry
```

Then `sentry-tui` will run without prompting for a password.

**For manual `sentry run` without sudo:**

The `sentry run` command works without sudo, but sees only unprivileged data. Use `sudo sentry run` for full visibility.

**Password not recognized?**

Use the full path if `sentry` is not in your sudo's PATH:

```bash
sudo /path/to/python/bin/sentry run --cycles 2
```

## Current limitations

This is an early, working version. A few things to know:

- New installs suppress noisy executable and listener alerts during the configured warmup period. High-signal rules remain active immediately.
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

## Complementary Tools

**Sentry** monitors continuously and detects changes. For a different angle on Linux security, see:

- **[spoorlog](https://github.com/sergeiredkin/spoorlog)** — Live forensic triage tool
  
  When Sentry alerts you to a change, run spoorlog to investigate instantly: "What changed? Why? Is it dangerous?"

Both tools are read-only, local-first, and designed for incident response teams. Use them together:
- **Sentry** watches continuously, catches baseline deviations
- **spoorlog** does fast deep investigation when you need answers now

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
