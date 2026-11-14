# Glossary

The terms used in the report, the app, the CLI and these docs. Where a
configuration key or JSON field keeps an older name, the entry says so.

**Tier Zero.** The objects that control the whole domain (domain controllers, Domain Admins, krbtgt, the AD CS servers and the GPOs above them); add more with `tier_zero = [...]`.

**Privilege Zone.** A set of objects you protect the way Pathwarden protects Tier Zero; see [privilege-zones.md](privilege-zones.md).

**Attack path.** A chain of relationships that lets whoever controls the first object take over the last.

**Account.** A user or a computer, the things that start an attack path; an **object** is anything in Tier Zero or a zone.

**Accounts with an attack path to Tier Zero.** The headline count: enabled users and computers outside Tier Zero that can reach it.

**Tier Zero exposure.** The share of active users and computers outside Tier Zero (logged on within `stale_days`) that have an attack path to it.

**Tier Zero protected.** The Tier Zero objects no open attack path finding leads to, as a count and a percentage ("53 of 59 objects (89.83%)"); **Protected** in a zone's row; the JSON key is `protected_percent` (`protection_score` until 2.0).

**Tier Zero status.** Critical, High, Moderate or Low, from the attack paths and open findings; never a score or a grade ([how it works](how-it-works.md#4-exposure-and-severity)); the JSON key is `exposure_status` (`exposure_grade` until 2.0).

**Status reason.** The one line that says why Tier Zero has its status, such as "2 critical findings are open"; the JSON key is `status_reason` (`grade_reason` until 2.0). The headline under the count is `reason`.

**Rule.** One check, such as PW-004; there are 38 ([rules.md](rules.md)).

**Finding.** One problem a rule found, with a severity, a category, an explanation and a fix.

**Finding ID.** A finding's stable identifier (`PW-004-13b08f...`), the same in every run while the problem exists; some JSON fields call it the fingerprint.

**Category.** *Attack Path* (a route to Tier Zero or a zone) or *Hygiene* (a weakness that is not a path on its own).

**Severity.** A finding's Critical, High, Medium, Low or Info; attack paths are rated by exposure, with a floor of High for direct control of the domain.

**Remediation path.** The smallest set of changes that leaves no attack path to Tier Zero (a minimum cut); `pathwarden plan --zone` works one out for a zone.

**Plan step.** One change in the remediation path, with the findings it closes and the attack paths it cuts.

**Fix directly.** A finding no plan step closes or cuts, such as a hygiene finding; it needs its own fix.

**Choke point.** One relationship that many attack paths cross (`pathwarden choke-points`).

**Accepted risk.** A finding you keep, with a reason and an optional **Review by** date; it isn't counted until that date (configuration `[[suppress]]` with `expires`, JSON `suppressed`).

**Environment.** A set of domains with its own settings, run history and schedule, such as **Demo** (`--env NAME`).

**Workspace.** The app's data folder on this computer; it is never encrypted.

**Run.** The result of one analysis.

**Run ID.** A run's ID in the run history, the time it started in UTC (`20261009T021000.042Z`).

**Run history.** An environment's runs, kept in a folder or a git repository, optionally encrypted; it keeps **Numbers with names** (the default) or **Full runs and settings** (configuration `[state]`, option `--state`).

**Sync.** Bringing a shared run history up to date in both directions (**Sync now**).

**Quick collection.** The built-in collector's default: the directory only, from a domain controller (`--scope dc-only`).

**Full collection.** A collection that also reads sessions and local groups from every computer (`--scope all`).

**Collection completeness.** The share of active computers whose sessions and local groups were collected; **Not targeted** means they weren't asked for.

**Explore.** The app's page for looking around a run; `reach`, `search`, `zones suggest` and `query` do the same on the command line.

**Demo.** The synthetic company built in, SCALE.LOCAL, with 10,000 computers and 15,000 users (`-i demo:`).

**New, open, back, fixed.** How a finding changed since the last run (JSON `regressed` for back, `resolved` for fixed).

**Since the last run.** What changed between the latest run and the one before it, one line per change.

**Introduced.** Net new over a period: new and back findings, findings that gained objects, new members and new paths.

**First seen.** The date of the run that first found a finding, object, member or path.

**New member.** An object that joined Tier Zero or a zone.

**New path.** A relationship into Tier Zero or a zone from outside it that wasn't there in the run before.

**Can't tell.** Pathwarden can't say whether a finding is fixed because its domain or source wasn't collected, so it stays open (JSON `held`).

**Retest.** Checking chosen findings again with a fresh collection; each gets **Fixed**, **Still open** or **Can't tell**.

**Evidence pack.** A signed zip for an auditor that shows a finding was fixed ([evidence.md](evidence.md)).

**Key fingerprint.** A short hash of the evidence signing key (`SHA256:NSrf...`) that an auditor checks a pack against.

**OpenGraph.** BloodHound's file format for other collectors' data ([opengraph.md](opengraph.md)).

**Mapping pack.** The reviewed rules that say what an OpenGraph source's relationships mean to the analysis.

**Kind.** The type of an object or relationship, such as `User` or `MemberOf`.
