# Docs style guide

How the pages in `docs/` are written. Terms are in the [glossary](glossary.md).

## Writing

- Cut. Say a thing once and link to it. Leave out background, rare edge
  cases and options `--help` already lists.
- Write short, complete sentences that end with a period, in lists and
  tables too.
- Say what the product does today, with no marketing words.
- Bold UI labels exactly as the app shows them (**Start analysis**); check
  them in `crates/pathwarden-ui`.
- Put commands in code (`pathwarden retest targeted --finding ID`); check
  them in `crates/pathwarden-cli`. The app's pages never name a command.
- Use the demo's names (SCALE.LOCAL, **Demo**), or **Lab**. Never a real
  organization's name, domain or data.
- Write **Tier Zero protected** as a count and a percentage, never a score
  or a grade.
- Write dates the US way: "Nov 10, 2026".

## Terms

- **Run history**, not state (`--state` and `[state]` keep their names).
- **Sync**; pull and push only for the git steps of `pathwarden run`.
- A **run** is a result; **analyze** is the verb.
- **Remediation path** and **plan step**; a **choke point** is one
  relationship.
- **Account** starts a path, **object** is in Tier Zero or a zone,
  **computer**, not host or machine; not "principal".
- **Accepted risk**, not suppression, with a **Review by** date.
- **Severity** for a finding, **status** for Tier Zero or a zone.
- **The app**, **couldn't**, **can't tell**, **first run**.

## Tasks

Each task gives the app first, then the command line:

```markdown
## Retest a finding

<!-- gif: the task's GIF, recorded with scripts/docs-media/record.mjs on the demo -->

### In the app

1. On a run page, open the **Findings** tab.
2. Click **Retest** in the finding's row.

### On the command line

    pathwarden retest targeted --finding PW-006-8ae0b31a46eacada --env Lab

More: [Retesting a finding](ui.md#retesting-a-finding).
```

- The headings are exactly **In the app** and **On the command line**. The
  website shows them as tabs.
- The recording comment becomes an image once recorded headless on the demo
  data, under 15 seconds ([scripts/docs-media](../scripts/docs-media/README.md)).
- One action per step, starting where the reader starts.
- When the app can't do the task, say so in one sentence.
- End with a "More:" line.
