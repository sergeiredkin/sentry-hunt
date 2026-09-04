# Contributing to Sentry

Sentry is a defensive, read-only monitoring tool. Keep the core principle: **Sentry only observes; it never modifies or fixes anything.**

## Before you PR

- **Test on a disposable system.** New collectors or rules should be tested on a fresh VM, not production.
- **Keep it read-only.** The tool must never write, delete, or modify system state. Observation only.
- **Match the architecture.** Collectors must use the push-based `ObservationSink` interface (see [DESIGN.md](docs/DESIGN.md) § 3), not return current state. This keeps continuous mode possible without rewrite.
- **Follow the interval model.** Store `first_seen` / `last_seen` / `still_present`, not just current state (§ 4.2).
- **Test in isolation.** Each collector and rule should be independently testable.

## How to run locally

```bash
git clone https://github.com/sergeiredkin/sentry-hunt.git
cd sentry-hunt
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
sentry run --cycles 1  # test run
```

## Submitting a PR

1. Link to or open an issue describing what you're improving.
2. Describe the use case: what threat-hunting goal does this serve?
3. Test it on a non-production system.
4. All tests pass: `pytest`.
5. One rule/collector per PR.

## Design principles (non-negotiable)

From DESIGN.md:
- **UI-agnostic engine** — core logic knows nothing about the TUI.
- **Read-only by default** — no writes, ever.
- **Local-first / offline** — no cloud, no required network calls.
- **Transparent** — every alert carries its evidence.
- **Modular** — each collector and rule is independent.
- **Continuous-ready** — collectors must work in both snapshot and event-driven modes.

See [DESIGN.md](docs/DESIGN.md) for full architecture.

## Questions?

Open an issue on GitHub or email sergei.redkin@gmail.com.
