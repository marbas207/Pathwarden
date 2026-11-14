# Rules reference

Pathwarden checks every collection against 38 rules, PW-001 to PW-039
(PW-024 is not used). `pathwarden rules` lists them, and `pathwarden guide
PW-003` prints a rule's step-by-step guide, with fix options, PowerShell,
verification and rollback.

An attack path finding's severity comes from the share of accounts in its
domain that can use it: Critical from 95%, High from 80%, Medium from 40%,
otherwise Low. Direct control of the domain ("at least High" below) is never
below High. Hygiene findings keep the rule's severity. `severity = "static"`
under `[rules]` uses the rules' own severities, and a severity your team sets
for a rule (Settings, or `[rules.severities]`) overrides both.

## Catalog

| Rule | Finding | Category | Severity |
|---|---|---|---|
| [PW-001](../crates/pathwarden-core/guides/PW-001.md) | A broad group (Domain Users, Authenticated Users, Everyone) has a path to Tier Zero. | Attack Path | From exposure, usually Critical. |
| [PW-002](../crates/pathwarden-core/guides/PW-002.md) | An account outside Tier Zero can DCSync. | Attack Path | At least High. |
| [PW-003](../crates/pathwarden-core/guides/PW-003.md) | An account outside Tier Zero controls a Tier Zero object. | Attack Path | At least High. |
| [PW-004](../crates/pathwarden-core/guides/PW-004.md) | A Tier Zero account is logged on to computers outside Tier Zero. | Attack Path | At least High. |
| [PW-005](../crates/pathwarden-core/guides/PW-005.md) | Unconstrained delegation outside the domain controllers. | Attack Path | At least High. |
| [PW-006](../crates/pathwarden-core/guides/PW-006.md) | A Kerberoastable account is in Tier Zero or has a path to it. | Attack Path | From exposure. |
| [PW-007](../crates/pathwarden-core/guides/PW-007.md) | An account doesn't require Kerberos pre-authentication (AS-REP roasting). | Attack Path if it reaches Tier Zero, else Hygiene. | From exposure, or Medium. |
| [PW-008](../crates/pathwarden-core/guides/PW-008.md) | Tier Zero accounts are neither in Protected Users nor marked sensitive. | Hygiene | Medium. |
| [PW-009](../crates/pathwarden-core/guides/PW-009.md) | Enabled Tier Zero accounts with no logon in 90 days. | Hygiene | Medium. |
| [PW-010](../crates/pathwarden-core/guides/PW-010.md) | Tier Zero passwords older than 365 days. | Hygiene | Medium. |
| [PW-011](../crates/pathwarden-core/guides/PW-011.md) | Computers without LAPS. | Hygiene | Medium. |
| [PW-012](../crates/pathwarden-core/guides/PW-012.md) | A trust lets forged SID history through (SID history enabled, or not quarantined). | Hygiene | High. |
| [PW-013](../crates/pathwarden-core/guides/PW-013.md) | Accounts that may have an empty password (PASSWD_NOTREQD). | Hygiene | High in Tier Zero, else Low. |
| [PW-014](../crates/pathwarden-core/guides/PW-014.md) | The krbtgt password hasn't been changed in 180 days. | Hygiene | Medium. |
| [PW-015](../crates/pathwarden-core/guides/PW-015.md) | AD CS ESC1: a template lets the requester choose any identity. | Attack Path | At least High. |
| [PW-016](../crates/pathwarden-core/guides/PW-016.md) | AD CS ESC3: an enrollment agent template. | Attack Path | At least High. |
| [PW-017](../crates/pathwarden-core/guides/PW-017.md) | AD CS ESC4: write access to a published template. | Attack Path | At least High. |
| [PW-018](../crates/pathwarden-core/guides/PW-018.md) | AD CS ESC6: the CA accepts requester-supplied SANs. | Attack Path | At least High. |
| [PW-019](../crates/pathwarden-core/guides/PW-019.md) | AD CS ESC8: web enrollment accepts relayed NTLM. | Attack Path | At least High. |
| [PW-020](../crates/pathwarden-core/guides/PW-020.md) | AD CS ESC9/ESC10: weak certificate mapping plus write access to an enrolling account. | Attack Path, or Hygiene when unverified. | At least High, or Medium. |
| [PW-021](../crates/pathwarden-core/guides/PW-021.md) | AD CS ESC13: an issuance policy linked to a group. | Attack Path | From exposure; at least High for a Tier Zero group. |
| [PW-022](../crates/pathwarden-core/guides/PW-022.md) | An account outside a [Privilege Zone](privilege-zones.md) controls an object in it. | Attack Path | From exposure. |
| [PW-023](../crates/pathwarden-core/guides/PW-023.md) | An account outside Tier Zero can log on to domain controllers remotely. | Hygiene | High; Critical for broad groups. |
| [PW-025](../crates/pathwarden-core/guides/PW-025.md) | A [management plane](#management-planes) manages Tier Zero but isn't declared Tier Zero. | Attack Path | At least High. |
| [PW-026](../crates/pathwarden-core/guides/PW-026.md) | A Group Policy Preferences file in SYSVOL holds a password. | Hygiene | Critical. |
| [PW-027](../crates/pathwarden-core/guides/PW-027.md) | A GPO's SYSVOL folder is writable by someone who can't edit the GPO. | Hygiene | High or Medium. |
| [PW-028](../crates/pathwarden-core/guides/PW-028.md) | A possible management plane to review. | Hygiene | High, Medium or Low, by the evidence. |
| [PW-029](../crates/pathwarden-core/guides/PW-029.md) | ESX Admins (CVE-2024-37085) is controlled from outside Tier Zero, or missing. | Hygiene | High, Medium or Low. |
| [PW-030](../crates/pathwarden-core/guides/PW-030.md) | An account outside Tier Zero controls Tier Zero through another system, from [OpenGraph](opengraph.md) data. | Attack Path | At least High. |
| [PW-031](../crates/pathwarden-core/guides/PW-031.md) | An account outside Tier Zero controls an Entra ID Tier Zero object ([Entra ID](entra.md)). | Attack Path | At least High. |
| [PW-032](../crates/pathwarden-core/guides/PW-032.md) | Entra ID controls an on-premises object that is Tier Zero or has a path to it. | Attack Path | At least High, or Medium. |
| [PW-033](../crates/pathwarden-core/guides/PW-033.md) | A Tier Zero password is stored by a service or scheduled task outside Tier Zero. | Attack Path | At least High. |
| [PW-034](../crates/pathwarden-core/guides/PW-034.md) | A SQL Server instance runs as a Tier Zero account (MSSQLHound data). | Attack Path | At least High. |
| [PW-035](../crates/pathwarden-core/guides/PW-035.md) | A Tier Zero computer is administered through SCCM from outside Tier Zero (ConfigManBearPig data). | Attack Path | At least High. |
| [PW-036](../crates/pathwarden-core/guides/PW-036.md) | AD CS ESC11: the CA accepts unencrypted requests over RPC. | Attack Path | At least High. |
| [PW-037](../crates/pathwarden-core/guides/PW-037.md) | The Seamless SSO account's Kerberos key is older than 30 days. | Hygiene | Medium. |
| [PW-038](../crates/pathwarden-core/guides/PW-038.md) | Tier Zero computers get updates from WSUS over plain HTTP. | Hygiene | High. |
| [PW-039](../crates/pathwarden-core/guides/PW-039.md) | Tier Zero computers are VMware virtual machines, whose hypervisor isn't modeled. | Hygiene | Medium. |

## AD CS coverage

| Technique | Covered by |
|---|---|
| ESC1 | PW-015. |
| ESC2 | PW-015 and PW-016. |
| ESC3 | PW-016. |
| ESC4 | PW-017. |
| ESC5, ESC7 | PW-003: the PKI objects and CAs are Tier Zero. |
| ESC6 | PW-018. |
| ESC8 | PW-019. |
| ESC9, ESC10 | PW-020. |
| ESC11 | PW-036, from a Full collection. |
| ESC13 | PW-021. |
| ESC14, ESC15 | Not yet. |

A CA counts only when domain controllers trust it for logon. Where the
domain controllers' registry couldn't be read, ESC9 and ESC10 are reported
as unverified; the [Tier Zero settings script](tier-zero-settings.md)
supplies it.

## Management planes

Systems such as Entra Connect, SCCM, SCOM, WSUS, Hyper-V and backup servers
can control Tier Zero outside AD permissions. Where the directory or the
[Tier Zero settings files](tier-zero-settings.md#management-agents) show
strong evidence that one manages a domain controller or CA server,
Pathwarden makes it Tier Zero and reports PW-025 until you add it to
`tier_zero`. Weaker evidence is reported for review as PW-028, never
guessed. If a detection is wrong, list the object under
`[management_planes] not_tier_zero`.
