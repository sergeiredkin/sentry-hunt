# Product direction: Sentry + spoorlog

## Research conclusion

The two projects should not compete with full SIEM/EDR products. Those products already win at fleet management, centralized search, and response automation. A useful product for this project is a **local Linux investigation loop**:

1. Sentry notices a meaningful change on one machine.
2. The user sees transparent evidence and decides whether it is expected.
3. spoorlog performs immediate, broad triage on the same machine.
4. The user can export a report or continue watching with Sentry.

This gives the projects a practical division of labor instead of two overlapping dashboards.

## Product promise

> Keep watching my Linux machine, explain what changed, and help me investigate it without sending my data anywhere.

The product must be useful to its developer first. It should run on the development workstation, tolerate normal development activity, and make it easy to distinguish expected changes from suspicious ones.

## Target first user

A technically capable Linux user, developer, or small-team operator who:

- owns the machine being inspected;
- does not want to operate a SIEM;
- needs local/offline operation;
- wants evidence, not an unexplained risk score;
- can approve or mute an expected change.

Do not optimize for enterprise fleet management yet.

## Differentiation

- **Sentry:** persistent, low-noise baseline monitoring and alert history.
- **spoorlog:** on-demand, broad forensic triage and export.
- **Together:** detection-to-investigation workflow on a single Linux host.

Avoid adding generic CPU monitoring, packet capture, malware scanning, cloud ingestion, or a large rule marketplace until real users demonstrate that the core loop needs them.

## Validation milestones

Before adding major features, dogfood the product on the developer workstation:

- Sentry runs for 14 days with a 60-second snapshot interval.
- Every alert is classified as expected, useful, or incorrect.
- Expected changes are suppressible without hiding a changed binary/hash.
- A useful alert can be investigated with spoorlog in under five minutes.
- The system records collector health and permission gaps so missing data is visible.

Success is not the number of rules. Success is: **the user keeps it running and trusts the alerts enough to investigate them.**

## Near-term roadmap

1. Configuration, warmup, suppression, and persistent baseline.
2. Dogfood mode: health status, alert feedback, and clean evidence export.
3. systemd service with safe resource limits and graceful restart.
4. Retention and database health.
5. Improve high-value rules using real false-positive data from the workstation.
6. Add a Sentry alert action/link that launches spoorlog triage and attaches the alert context.
7. Only then evaluate continuous event sources.

## Product guardrails

- Read-only monitoring by default.
- No mandatory network service.
- No opaque ML verdicts.
- Every alert explains the evidence and collection limitations.
- Rules must be tested against normal developer behavior before being promoted.
