# Local Linux Threat-Hunting Tool — MVP Build Specification

> **Note:** This document was written as build instructions for an AI coding assistant during development. It is kept here as the detailed design reference: data model, rules, and architecture.

> **Audience:** Claude Code (implementation agent).
> **Goal:** Build a single-user, local-first, investigation-oriented threat-hunting tool for a Linux workstation. This document is the authoritative spec for the MVP. Follow it precisely. Where it says "configurable," expose the value in config; do not hardcode.

---

## 1. Product summary

A background engine collects system telemetry on a timer, stores it as time-interval observations in SQLite, diffs each snapshot against the established baseline, evaluates a fixed set of threat-hunting rules, and surfaces alerts through a terminal UI. The guiding question the tool answers is **"what changed, and should I care?"**

**Design principles (non-negotiable):**
- **UI-agnostic engine.** The engine and storage know nothing about the UI. The TUI is a consumer of the same data any future UI (or the continuous-mode collector) will use.
- **Read-only by default.** The tool never modifies the monitored system. It only observes.
- **Local-first / offline.** No mandatory cloud services. No network calls required for core function.
- **Transparent.** Every alert carries the evidence that produced it. No black-box verdicts.
- **Modular.** Every collector and every rule is an independent, testable unit behind a shared interface.

**Explicitly OUT of scope for MVP** (design for them, do not build them): packet capture, YARA/ClamAV/VirusTotal, entropy analysis, DuckDB, ML/statistical anomaly detection, GUI (Qt/PySide6), general recursive directory file-integrity scanning, fleet/multi-host anything.

---

## 2. Architecture

```
              +------------------------+
              |     Textual TUI        |   (consumer only)
              +-----------+------------+
                          | reads
              +-----------v------------+
              |        SQLite          |   (SQLAlchemy + Alembic)
              +-----------^------------+
                          | writes
   ingest -> persist -> diff -> evaluate -> alert   (Engine pipeline)
      ^
      | ObservationSink (push interface)
      |
  [ collectors ]  process | network | users | persistence | auth-journal | file-integrity
      ^
      | driven by
   Scheduler (APScheduler)   <-- snapshot mode: calls collectors on a timer
```

The five pipeline stages are **decoupled and joined through the database**, not chained in one function:

1. **ingest** — a collector emits observations into an `ObservationSink`.
2. **persist** — the sink writes observations to SQLite using the interval-upsert logic (§4.2).
3. **diff** — the diff engine computes what is new / changed / gone since the last baseline.
4. **evaluate** — the rule engine runs the six rules over the diff + recent observations.
5. **alert** — matched rules produce alerts (subject to warmup and suppression).

Ingestion cadence and evaluation cadence are separate. In MVP both are timer-driven at the same interval, but they must be independently schedulable so that continuous-mode ingestion (later) can write constantly while evaluation still runs on a timer.

---

## 3. The critical design constraint: snapshot now, continuous later

The MVP runs in **snapshot mode** (collect full state every 60s). The **next phase** is **continuous mode** (event-driven, btop-style, sub-second, via an OS event source). The schema and collector interface **must support both without a rewrite.** This is the single most important architectural requirement.

The mechanism that makes this work: **model state as intervals, not as current values.** Snapshots are just a low-resolution way of populating an interval model; an event stream is a high-resolution way of populating the *same* model. Everything downstream (diff, rules, TUI) reads the interval model and is mode-agnostic.

**Do NOT** build "current state" tables that get truncated and rewritten each cycle. **Do** build observation tables with `first_seen` / `last_seen` / `still_present` (§4.2).

**Collectors must be push-shaped.** A collector does not `return` the current state; it emits observations into a sink:

```python
class Collector(Protocol):
    name: str
    respects_warmup: bool          # see §7

    def collect(self, sink: "ObservationSink") -> None:
        """Snapshot mode: engine calls this on a timer.
        Continuous mode (future): a collector calls sink.emit(...) on each OS event.
        Same sink, same downstream."""
        ...

class ObservationSink(Protocol):
    def emit(self, observation: "Observation") -> None: ...
```

Any collector written as `get_current_state() -> list` is wrong and will force a rewrite later. Enforce the push interface from the first collector.

---

## 4. Data model

Use **SQLAlchemy** for the ORM and **Alembic** for migrations from commit one. Every schema is versioned; never edit a table by hand.

### 4.1 General conventions
- All timestamps stored UTC, ISO-8601, timezone-aware.
- All hashes are SHA-256, lowercase hex.
- The DB file lives at a configurable path (default `~/.local/share/<appname>/state.db`), created with `0600` permissions.

### 4.2 Interval model (the core pattern)

Entities that have "presence over time" (processes, network sockets, and each inventory item) use this shape. Example for processes:

```
process_observations
  id                INTEGER PK
  pid               INTEGER
  ppid              INTEGER
  exe_path          TEXT
  sha256            TEXT NULL        # null if unreadable (permissions)
  cmdline           TEXT
  user              TEXT
  first_seen        TIMESTAMP
  last_seen         TIMESTAMP
  still_present     BOOLEAN
  identity_key      TEXT             # stable dedup key, e.g. hash(pid, ppid, exe_path, start_time)
```

**Upsert logic each cycle (snapshot mode):**
- Observed and an open matching observation exists (`still_present = true`) → update `last_seen = now`.
- Observed and no open match → insert new row, `first_seen = last_seen = now`, `still_present = true`.
- Previously open but not observed this cycle → set `still_present = false`, leave `last_seen` at its last value.

The identical logic works in continuous mode: an exec event does the insert, an exit event does the "not observed → close" step. **The diff engine, rules, and TUI never change between modes** — only who calls the upsert and how often.

`still_present = true` is the cheap answer to "what is running right now" (needed for the btop-style view).

Apply the same interval pattern to `network_observations` (listening + established sockets) and to inventory tables where "currently present" is meaningful.

### 4.3 Inventory / baseline tables
- `system_inventory` — CPU, RAM, disks, kernel, uptime (point-in-time snapshots; keep latest + rollups).
- `users_groups` — accounts, UID/GID, group membership, sudoers state.
- `persistence_entries` — systemd units (system+user), cron jobs, systemd timers, autostart entries, shell-rc-derived entries; store the command each runs.
- `file_integrity` — the narrow critical-file set (§6, rule 6): path, sha256, size, owner, perms, mtime.
- `packages` — installed packages (collected for inventory/baseline; no dedicated MVP rule, but rule-1 context and future rules use it).

### 4.4 Alerts and suppressions

```
alerts
  id            INTEGER PK
  rule_id       TEXT
  severity      TEXT           # LOW | MEDIUM | HIGH
  created_at    TIMESTAMP
  status        TEXT           # active | acknowledged | suppressed_warmup | muted
  title         TEXT
  evidence_json TEXT           # structured evidence, see each rule spec
  dedup_key     TEXT           # so the same finding doesn't spam every cycle
```

```
suppressions
  id           INTEGER PK
  rule_id      TEXT
  scope        TEXT            # path_hash | path | hash | exact_event | rule_global
  match_value  TEXT            # the value compared against, per scope
  reason       TEXT
  created_at   TIMESTAMP
  expires_at   TIMESTAMP NULL  # null = permanent; non-null = temporary mute
  created_by   TEXT            # 'user' | 'system'
```

- **Warmup-suppressed** alerts are still written (status `suppressed_warmup`) — never discarded. This keeps warmup testable and auditable.
- Before surfacing any alert, the evaluate stage checks active (non-expired) suppressions. Matching semantics per scope in §8.

---

## 5. Collection cadence and data sources

- **Snapshot interval:** default **60 seconds**, configurable (`snapshot_interval_seconds`).
- **Known, documented limitation:** at 60s, process/network snapshots **miss any entity that lives less than one interval** (short-lived reverse shells, `curl|bash` droppers, quick exfil). This is expected and is the reason continuous mode exists. State it in user-facing docs; do not pretend the tool is lossless where it isn't.
- **Lossless vs sampled** — sources differ and rules must be tagged accordingly:

| Source | Nature | Rules relying on it |
|---|---|---|
| journal (auth) | **Lossless** — complete historical record | 5 |
| inventory diff (users, persistence) | **Lossless** — full state compared each cycle | 2, 4 |
| file integrity | **Lossless** — full state compared each cycle | 2, 4, 6 |
| process snapshots | **Sampled** — 60s blind spot | 1, (3 evidence) |
| network snapshots | **Sampled** — 60s blind spot | 3 |

---

## 6. The six MVP rules

Each rule is an independent, testable unit implementing a shared `Rule` interface:

```python
class Rule(Protocol):
    id: str
    default_severity: str
    respects_warmup: bool
    def evaluate(self, ctx: "EvalContext") -> "list[Finding]": ...
```

`EvalContext` exposes the current diff, recent observations, and baseline history. A `Finding` carries severity (which may differ from `default_severity` per the escalation logic), a `dedup_key`, and structured `evidence`.

### Rule 1 — New executable observed
- **Watches:** process observations.
- **Triggers:** an `(exe_path, sha256)` pair whose `first_seen` is in this window and which has never appeared in baseline history.
- **Severity:** LOW by default; escalate to **MEDIUM** if `exe_path` is under `~/Downloads`, `/tmp`, `/dev/shm`, or `/var/tmp`.
- **Source:** process snapshots (**sampled**).
- **respects_warmup:** **true** (noisy — every `pip`/`npm`/compiler/pkg-update trips it).
- **Evidence:** path, sha256, cmdline, ppid + parent exe, user, first_seen, any concurrent network connections by the same PID.

### Rule 2 — New sudo / privileged user or group change
- **Watches:** users/groups inventory — membership of sudo/wheel, `/etc/sudoers`, `/etc/sudoers.d/*`, new UID-0 accounts.
- **Triggers:** user added to sudo/wheel; new UID-0 account; change to any sudoers file.
- **Severity:** **HIGH**.
- **Source:** inventory diff + file integrity on sudoers (**lossless**).
- **respects_warmup:** **false** (live from minute one).
- **Evidence:** username, UID/GID, before/after group membership, which sudoers file changed, mtime, timestamp.

### Rule 3 — New listening port / service
- **Watches:** network observations (LISTEN sockets).
- **Triggers:** a port enters LISTEN that wasn't in baseline, OR a known port changes its owning process.
- **Severity:** MEDIUM default; **LOW** if bound to loopback (`127.0.0.1`/`::1`); **HIGH** if bound to `0.0.0.0`/`::` with an unexpected owning process.
- **Source:** network snapshots (**sampled**).
- **respects_warmup:** **true**.
- **Evidence:** port, protocol, bind address, owning PID + exe + sha256, user, first_seen.

### Rule 4 — New persistence entry
- **Watches:** systemd units (system + user), cron (all crontabs + `/etc/cron.*`), systemd timers, `~/.config/autostart`, shell rc files (`.bashrc`, `.profile`, `.zshrc`).
- **Triggers:** a new unit/timer/cron/autostart entry appears, OR an existing entry's `ExecStart`/command changes.
- **Severity:** **HIGH** (persistence is the strongest single attacker signal).
- **Source:** inventory + file-integrity diff (**lossless**).
- **respects_warmup:** **false**.
- **Evidence:** mechanism type (systemd/cron/timer/autostart/rc), unit-or-file path, the command it runs, mtime, before/after for changes.

### Rule 5 — Failed-login spike / auth anomaly
- **Watches:** journal auth facility (sshd, sudo, PAM, login).
- **Triggers:** failed auth exceeds threshold in a window (**default: >5 failures for one account, or >10 total, per 10 min** — both configurable), OR a successful login from a never-before-seen source (new username, or new remote IP for SSH).
- **Severity:** MEDIUM; **HIGH** if a spike is immediately followed by a **success** (brute force that landed).
- **Source:** journal (**lossless**).
- **respects_warmup:** **false**.
- **Evidence:** account(s), source IP(s), count, time window, whether any attempt succeeded, service.

### Rule 6 — Changed critical config / system binary
- **Watches (narrow fixed list, ~15 files — NOT recursive):** `/etc/ssh/sshd_config`, `~/.ssh/authorized_keys`, `~/.ssh/config`, `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, plus SHA-256 of key binaries in `/usr/bin` and `/usr/local/bin` (list configurable).
- **Triggers:** hash change on a watched file; a new SSH authorized key; permission/owner change on a watched file.
- **Severity:** **HIGH** for ssh/passwd/shadow and binary changes; **MEDIUM** for others.
- **Source:** file-integrity diff (**lossless**).
- **respects_warmup:** **false**.
- **Evidence:** file path, old→new hash, old/new perms + owner, mtime; for authorized_keys, the specific key added.

**MVP collector list is fixed by these rules:** process, network, users/sudo, persistence, auth-journal, critical-file-integrity. File integrity is **in** the MVP but scoped to the ~15-file critical list only — general directory scanning is deferred.

---

## 7. Warmup

- **Default warmup:** **7 days**, configurable (`warmup_days`).
- During warmup, rules still run and populate baseline history. Alerts from **warmup-respecting** rules are written with status `suppressed_warmup` (stored, not surfaced). This keeps the data for testing and audit.
- **Per-rule:** `respects_warmup`. Only rules **1** and **3** respect warmup. Rules **2, 4, 5, 6** are **live immediately** — a new UID-0 account or new persistence entry on day 2 is exactly what the tool exists to catch, not baseline noise.
- **Dev/test override:** `--skip-warmup` flag / config value sets effective warmup to 0. Required for integration tests and local development; it is a first-class config value, not a test-only code path.

---

## 8. Suppression (ack / mute) semantics

MVP UI exposes two actions per alert:
- **Acknowledge** → creates a suppression with scope `exact_event` (silences this one finding instance).
- **Mute** → creates a suppression with the rule-appropriate default scope:
  - File/exec rules (1, 6) → `path_hash` (this binary at this path; a swapped binary re-alerts because the hash changed).
  - Other rules (2, 3, 4, 5) → `exact_event`.

Scope matching:
- `path_hash` — matches when both path and sha256 equal `match_value` (encode both).
- `path` — matches on path regardless of hash (advanced, opt-in; **never** the default for binaries, since it would silence a replaced binary).
- `hash` — matches this exact binary wherever it appears.
- `exact_event` — matches one specific finding (by dedup_key).
- `rule_global` — mutes an entire rule (escape hatch).

`expires_at`: MVP UI always sets it null (permanent), but the column exists and is settable via config/CLI so temporary mutes ("silence 24h during migration") need no later migration. The evaluate stage ignores expired suppressions.

**Why these scopes exist now:** they are the seams the test suite exercises (feed synthetic observations → assert alert fires → assert scope X silences it and scope Y does not). They are data, not hardcoded logic, so tests manipulate them directly.

---

## 9. Retention

- Raw process/network observations: **30 days** (configurable).
- Daily baseline rollups: **1 year** (configurable).
- Alerts: **indefinite** (low volume, history is valuable).
- Implement a compaction/prune job on a schedule. Retention values are config, adjustable per user.

---

## 10. Technology stack (MVP)

| Concern | Choice |
|---|---|
| Language | Python 3.11+ |
| ORM / migrations | SQLAlchemy + Alembic |
| Storage | SQLite |
| Scheduler | APScheduler |
| System introspection | `psutil`, `pathlib`, `subprocess` |
| Journal access | `journalctl` via subprocess (or python-systemd if available) |
| TUI | **Textual** (reactive, testable, mouse support) |
| Config | TOML file + env-var overrides |
| Tests | `pytest` |

Deferred (design seams only, do not implement): eBPF (`bcc`/`bpftrace`) or `proc connector` for continuous mode; DuckDB; YARA/ClamAV; Qt GUI.

---

## 11. Privilege & platform notes

- Much useful collection (other users' processes, `/etc/shadow`, auth journal, `/usr/bin` hashing) needs elevated capability. Target running the engine as a **systemd service with specific capabilities** (`CAP_DAC_READ_SEARCH` for reads; add others only as needed) rather than blanket root. Degrade gracefully: if a source is unreadable, record `sha256 = null` / mark the item unavailable rather than crashing.
- **Distro abstraction:** package manager (apt/dnf), service enumeration, and log layout differ across Debian/Ubuntu/Fedora/Rocky. Put these behind a small platform layer so collectors call an abstraction, not a hardcoded command. The tool must work across those distros.

---

## 12. Project structure

```
<appname>/
  engine/
    pipeline.py          # ingest -> persist -> diff -> evaluate -> alert
    sink.py              # ObservationSink
    diff.py              # baseline diff engine
    scheduler.py         # APScheduler wiring
  collectors/
    base.py              # Collector protocol
    process.py
    network.py
    users.py
    persistence.py
    journal_auth.py
    file_integrity.py
  rules/
    base.py              # Rule protocol, EvalContext, Finding
    r1_new_executable.py
    r2_priv_change.py
    r3_new_listener.py
    r4_persistence.py
    r5_auth_anomaly.py
    r6_critical_change.py
  suppression/
    scopes.py            # scope matching logic
  storage/
    models.py            # SQLAlchemy models
    migrations/          # Alembic
  platform/
    base.py              # distro abstraction
  tui/
    app.py               # Textual app: health dashboard + drill-down
  config/
    defaults.toml
  tests/
```

---

## 13. Build order (phased tasks for Claude Code)

1. **Storage + migrations.** SQLAlchemy models for the interval + inventory + alerts + suppressions tables; Alembic baseline migration; DB created at `0600`.
2. **Sink + upsert.** `ObservationSink` and the interval-upsert logic (§4.2), with unit tests for insert/update/close transitions.
3. **Collector interface + process collector.** Push-shaped `Collector`; implement `process.py` first; test it drives the sink correctly.
4. **Remaining collectors:** network, users, persistence, journal_auth, file_integrity. Each behind the platform abstraction; each with tests using fixture data.
5. **Diff engine.** Compute new/changed/gone from the interval model; tests over synthetic baselines.
6. **Rule engine + the six rules.** Each rule as an independent unit with its own tests: synthetic input → assert finding + severity (incl. escalation paths).
7. **Warmup + suppression.** `respects_warmup` handling; suppression scope matching; `--skip-warmup`. Tests: warmup stores-but-hides for rules 1/3, rules 2/4/5/6 fire during warmup; each scope silences the right thing and not the wrong thing; expired suppressions ignored.
8. **Scheduler.** APScheduler drives collection at `snapshot_interval_seconds`; ingestion and evaluation independently schedulable.
9. **Retention/compaction job.**
10. **Textual TUI.** Health dashboard (overall risk, counts, alert list) + drill-down showing full evidence per alert; Acknowledge and Mute actions wired to the suppression layer.
11. **Config + docs.** TOML defaults, env overrides; user-facing README stating the 60s sampled-vs-lossless limitation and the privilege model.

---

## 14. Testing expectations

- Every collector, rule, the diff engine, the upsert logic, and every suppression scope has unit tests with synthetic/fixture data — no dependence on the live host state.
- Integration test runs the full pipeline with `warmup_days = 0` against seeded observations and asserts the correct alerts surface.
- Rules are tested for both the trigger and the **non-trigger** (baseline-normal input produces no finding) and for severity escalation branches.
- Suppression tests assert both silencing (correct scope hides the alert) and leakage-prevention (wrong scope does **not** hide it, swapped-binary re-alerts under `path_hash`).

---

## 15. Continuous-mode readiness checklist (for the phase after MVP — do not build now, but do not violate)

- [ ] Observations are interval-shaped (`first_seen`/`last_seen`/`still_present`), never truncate-and-replace.
- [ ] Collectors are push-shaped (`collect(sink)` / `sink.emit`), never `get_current_state()`.
- [ ] Ingestion cadence is decoupled from evaluation cadence.
- [ ] `still_present` answers "running now" cheaply for the btop-style live view.
- [ ] Diff engine, rules, and TUI read only the interval model and are cadence/mode agnostic.

If all five hold, dropping in an event source (`proc connector` first, eBPF later) is an additive change, not a rewrite.
