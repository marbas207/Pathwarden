# Entra ID and hybrid paths (AzureHound data)

Pathwarden reads [AzureHound](https://github.com/SpecterOps/AzureHound)
output next to your AD collection and reports attack paths that cross
between Active Directory and Entra ID. It covers the Entra directory, not
Azure resources such as subscriptions, VMs or Key Vaults.

## Add AzureHound data

### In the app

1. In the rail, click **Analyze**, then **A previous collection**.
2. Add the AD collection and the AzureHound `.json` file together.
3. Click **Start analysis**.

For a run you collected in the app, open **Run details** and click **Add
files and analyze again**. This needs the raw collection to have been kept.

### On the command line

```sh
azurehound list az-ad -u "<user>" -p "<password>" -t "<tenant>" -o azurehound.json
pathwarden report -i corp-sharphound.zip -i azurehound.json -o report.html
```

`list az-ad` is enough. AzureHound data alone is not a collection:
Pathwarden still needs the AD data. The report lists the tenant under
**Data sources**.

## What it finds

| Rule | Reports |
|---|---|
| [PW-031](../crates/pathwarden-core/guides/PW-031.md) | An account outside Tier Zero controls an Entra Tier Zero object, such as an AD account synchronized to a Global Administrator. At least High. |
| [PW-032](../crates/pathwarden-core/guides/PW-032.md) | Entra ID controls an AD object that is Tier Zero or has a path to it, through password writeback or Intune. |

Entra Tier Zero is the tenant, the Global, Privileged Role and Privileged
Authentication Administrator roles, Directory Synchronization Accounts,
their holders (active or eligible), and service principals with
RoleManagement.ReadWrite.Directory or AppRoleAssignment.ReadWrite.All. Entra data never makes an AD object Tier Zero. Add an
Entra object ID to `tier_zero` to treat it as Tier Zero.

## Limits

- MFA and Conditional Access are not modeled: a synchronized account's AD
  password is treated as signing in to Entra ID.
- AzureHound can't see whether password writeback is on. If it is off,
  writeback paths are false positives: confirm in Entra Connect.
- Roles scoped to an administrative unit, delegated permissions and Azure
  RBAC are not modeled.

## Can't tell

A tenant counts as collected only when the file has the tenant, at least
one user and one role assignment, and was read whole. Otherwise its
findings are held, never resolved. With no AzureHound data, every other
attack path finding is held too
([Can't tell](opengraph.md#cant-tell-and-held-findings)).

AzureHound doesn't record API failures in its output, so a listing that
failed part way looks like a smaller tenant. Check its log after each
collection.

## What can go wrong

| Problem | Fix |
|---|---|
| No Entra findings, and no tenant under **Data sources**. | Give the AzureHound file in the same analysis as the AD data. |
| The tenant's findings are held. | Collect again with an account that can list users and role assignments, and check AzureHound's log. |
| "AzureHound read part way". | Raise the `[opengraph]` limits, or collect with `list az-ad` only. |
| A synchronized user or hybrid-joined computer has no link. | Collect that object's domain. |
