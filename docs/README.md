# Pathwarden documentation

## Evaluating Pathwarden

- [Coverage comparison](coverage.md) with BloodHound Enterprise and
  BloodHound CE.
- [How it works](how-it-works.md).
- [Rules](rules.md).
- [Entra ID and hybrid paths](entra.md).
- [OpenGraph data](opengraph.md).
- [Glossary](glossary.md).
- [Sample report](sample-report.html) and the [demo data](../demo/README.md).

## Using Pathwarden

- [Getting started](getting-started.md).
- [Tasks, step by step](tasks.md).
- [The app](ui.md).
- [Collecting](collect.md).
- [A least-privilege collector account](collector-account.md).
- [Tier Zero settings (DCs and CAs)](tier-zero-settings.md).
- [Configuration](../pathwarden.example.toml).
- [Privilege Zones](privilege-zones.md).
- [Scheduled runs](running.md).
- [Evidence packs](evidence.md).
- [Output plugins](plugins.md), with the
  [ServiceNow](../crates/pathwarden-output-servicenow/README.md) and
  [Jira](../crates/pathwarden-output-jira/README.md) plugins.
- [Integrations](integrations.md): SARIF, DefectDojo, Jira and PingCastle.
- [Using finding actions](finding-actions.md): set up the example buttons
  on a finding (a chat alert, a ticket, an owner lookup).
- [Writing an action](actions.md): your own buttons on a finding, with the
  [examples and helpers](../examples/actions/README.md).

## For developers and reviewers

- [Building from source](dev/building.md).
- [Threat model](dev/threat-model.md).
- [File formats and upgrades](dev/formats.md).
- [Docs style guide](style.md).
- [Roadmap](../ROADMAP.md).
