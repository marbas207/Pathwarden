# vCenter and CyberArk: design note

*Status: design only. No mapping pack ships for either.*

vCenter runs the domain controllers' virtual machines, and CyberArk holds
the Domain Admins' passwords, so both control Tier Zero. Their OpenGraph
collectors aren't usable: vCenterHound and CyberArkHound have no license,
give one edge for every role or permission, and don't join their data to AD
reliably. Paths built on them would be wrong.

## What to do today

Declare the systems Tier Zero, so the existing rules and the remediation
path cover who controls them:

```toml
# vCenter servers, and the CyberArk PVWA, CPM and PSM servers
tier_zero = ["VCENTER01.SCALE.LOCAL", "PVWA01.SCALE.LOCAL", "CPM01.SCALE.LOCAL", "PSM01.SCALE.LOCAL"]
```

PW-039 already reports Tier Zero computers that run VMware Tools.

## vCenter: a native connector, later

A read-only connector over verified TLS would match each Tier Zero computer
to its virtual machine, work out who holds dangerous privileges on it
(snapshots, console, disks, datastores, permissions), resolve those
principals to AD accounts, and add a `HypervisorControl` relationship and
an Attack Path finding, at least High. Effort: 4 to 6 days, with a vCenter
evaluation lab.

## CyberArk: ingest on demand

When a user with CyberArk asks, Pathwarden would read CyberArk's own data
and do the AD join itself. Paths would come only from permissions that
retrieve a password without dual control, or that grant that access. The
finding would be "Non-Tier Zero principals can retrieve Tier Zero
credentials from CyberArk", and the vault servers would be Tier Zero.
Effort: about 2 days, once there is data to test against.
