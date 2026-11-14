# Coverage: Pathwarden, BloodHound Enterprise and BloodHound CE

Pathwarden next to SpecterOps' commercial **BloodHound Enterprise** (BHE)
and the free **BloodHound Community Edition** (CE).

*Pathwarden 0.3.0 (Nov 10, 2026); BloodHound v9.8.0 (Oct 7, 2026), from
SpecterOps' public documentation and code ([sources](#sources)). "Not
public" marks what is visible only inside a BHE tenant.*

**Legend:** ✅ yes · 🟡 partial · ❌ no

## In short

Pathwarden covers BHE's core model for on-premises Active Directory in one
free executable with no database or server.

**Beyond BHE:** a complete minimum-change remediation path, step-by-step
guides per rule, AD CS ESC2, ESC5 and ESC7, output plugins in any language,
a run history in plain files or git, a self-contained HTML report, and
signed evidence packs.

**Not covered:** Azure resources, all of CE's Cypher, managed collector
agents, a REST API, first-party SIEM integrations, multi-user access, AD CS
ESC14 and ESC15, Authenticode-signed executables and vendor support.

## Attack path management and remediation

| Capability | Pathwarden | BHE | CE |
|---|---|---|---|
| Findings engine | ✅ 38 rules | ✅ (catalog not public) | ❌ manual queries |
| Exposure, severity from exposure | ✅ same 95/80/40% bands, at least High for direct domain control | ✅ | ❌ |
| Tier Zero, auto-identified | ✅ includes AD CS hosts, GPOs linked to Tier Zero and management planes | ✅ | ✅ |
| Custom Privilege Zones | ✅ | ✅ (paid add-on) | ❌ |
| Zone rules as queries, approval | ❌ | ✅ | ❌ |
| Risk acceptance | ✅ by finding or rule, with a reason and review date | ✅ per account, for N days | ❌ |
| Finding lifecycle | ✅ new, open, back, accepted risk, fixed, can't tell | ✅ | ❌ |
| Trends over time | 🟡 run history and **Progress** | ✅ Posture page | ❌ |
| Choke points | ✅ | ✅ | ❌ |
| Smallest complete set of changes | ✅ minimum cut | 🟡 choke points only | ❌ |

## Detection coverage

| Area | Pathwarden | BHE |
|---|---|---|
| Control of Tier Zero, DCSync, large groups with a path | ✅ PW-001 to PW-003 | ✅ |
| Tier Zero sessions, unconstrained delegation, Kerberoasting | ✅ PW-004 to PW-006 | ✅ |
| AS-REP roasting, stale accounts, LAPS, SID filtering, DC logon rights | ✅ | Not public |
| SYSVOL and NETLOGON write access, GPP passwords | ✅ built-in collector | ❌ |
| Passwords stored by services and tasks | 🟡 PW-033 | ❌ (TaskHound adds it) |
| Relay attacks beyond AD CS | ❌ | ✅ |
| AD Sites | ❌ | ✅ |
| Management planes controlling Tier Zero | 🟡 Entra Connect, SCOM, SCCM, WSUS, Hyper-V, ESX Admins | 🟡 through OpenGraph |
| Entra ID and hybrid | 🟡 no Azure resources ([entra.md](entra.md)) | ✅ |
| OpenGraph sources | 🟡 reviewed mapping packs ([opengraph.md](opengraph.md)) | ✅ |

**AD CS:** Pathwarden covers ESC1 to ESC11 and ESC13 and Golden
Certificates, but not ESC12, ESC14, ESC15 or ESC16. BloodHound covers ESC1,
ESC3, ESC4, ESC6, ESC8 to ESC10, ESC13, ESC14 (Scenario A) and Golden
Certificates, with generic edges for ESC5 and ESC7
([AD CS coverage](rules.md#ad-cs-coverage)).

## Collection, reporting and deployment

| Capability | Pathwarden | BHE | CE |
|---|---|---|---|
| SharpHound and RustHound-CE output | ✅ v5 and v6 | ✅ | ✅ |
| Built-in collector | ✅ full build | ✅ SharpHound Enterprise | ❌ |
| Central management of collectors | ❌ | ✅ | ❌ |
| Incomplete collections | ✅ marked "can't tell" | ✅ | ❌ |
| Graph explorer, Cypher | 🟡 Explore and a part of CE's Cypher | ✅ | ✅ |
| Scale | ✅ 500,000 computers and 750,000 users in 23 seconds and 2.7 GB | Not public | 96 GB and 12 cores above 50,000 users |
| Shareable report | ✅ self-contained HTML | 🟡 | 🟡 CSV |
| Evidence for auditors | ✅ signed packs ([evidence.md](evidence.md)) | ❌ | ❌ |
| Ticketing | ✅ ServiceNow and Jira | ✅ | ❌ |
| SARIF, DefectDojo | ✅ ([integrations.md](integrations.md)) | 🟡 through the API | ❌ |
| SIEM and SOAR | 🟡 through a plugin | ✅ | ❌ |
| REST API | ❌ `--json` and the event document | ✅ | ✅ |
| What you run | One executable | SaaS, or on-premises Kubernetes | Docker: PostgreSQL and Neo4j |
| Users, roles, SSO | ❌ single user | ✅ | ✅ |
| Compliance | ❌ | ✅ FedRAMP High | ❌ |
| License and price | Free, Apache-2.0 | Subscription; AWS Marketplace from $30.90 per employee, $77,250 minimum | Free, Apache-2.0 |

What's next is in the [roadmap](../ROADMAP.md).

## Sources

Accessed Oct 9, 2026:

- BloodHound documentation: <https://bloodhound.specterops.io/> (findings,
  Privilege Zones, collection, integrations, deployment, users and roles).
- Release notes: <https://bloodhound.specterops.io/resources/release-notes/>
- Editions: <https://specterops.io/bloodhound-feature-comparison/>
- AD CS edges: <https://github.com/SpecterOps/BloodHound>
  (`packages/go/graphschema/ad/ad.go`)
- Pricing: <https://aws.amazon.com/marketplace/pp/prodview-nne5kiarmhfwi>
