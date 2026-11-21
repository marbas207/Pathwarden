# Roadmap

Goal: the attack path management workflow of BloodHound Enterprise (scheduled
collection, prioritized findings, a remediation path, trends and remediation
tracking) as a free tool for Windows and Linux.

What ships today is in [docs/coverage.md](docs/coverage.md). This page lists
what is next. The open issues on GitHub are the detailed list.

## 1.0 release candidates

1.0.0-rc.4 is out: clearer wording across the app, fixed findings whose
ticket is still open, and plain LDAP where LDAPS fails. From here to 1.0,
release candidates carry fixes and making existing features easier to use.

- **1.0.0-rc.5:** add a finding action from a shipped example, and a guide
  for using finding actions. Fixes reported against rc.4.
- **1.0:** when the release candidates have run without new problems.

## After 1.0

- **Blast radius:** everything one account can take over, for incident
  response ("this account was phished: what can it reach?").
- **What-if:** remove a set of relationships or objects and see the exposure
  before and after.
- **Measured fixes:** every finding says what fixing it removes, with a
  recomputed remediation path.
- **Fix scripts:** a reviewed PowerShell script per fix, with checks and an
  undo.
- **Alerts** in Microsoft Teams, Slack, email or a webhook when a run gets
  worse. Today a short script does this ([docs/plugins.md](docs/plugins.md)).
- **Tickets in the app:** each finding's ticket number, link and state in the
  app, the report and the command line.
- **Explore** reorganized around its jobs: findings, objects, queries and
  zones. Cypher queries turned into finding rules, tracked across runs.
- **AD CS** ESC14 and ESC15 (EKUwu).
- **Azure resources** (subscriptions, VMs and Key Vaults). Entra ID objects,
  roles and Graph application permissions are covered
  ([docs/entra.md](docs/entra.md)).
- **More data sources** through OpenGraph (for example vulnerability scanners
  and EDR session data), and OpenGraph collector plugins.
- **Logon footprint:** where Tier Zero accounts have logged on.
- **Hygiene:** unexpected shadow credentials and restorable tombstones.
- **Collection:** spread across several domain controllers, incremental
  collection, and Kerberos on Linux without system libraries.

## Ideas

- Network-aware paths that drop relationships a segmentation map blocks, and
  starting points weighted by known-vulnerable computers (from Zero Networks'
  BloodHound-Tools).
- Optional sandboxed in-process plugins (WebAssembly) if the executable model
  proves too limiting.
- A desktop window on Linux. Today `pathwarden ui` opens the app in the
  browser there.
