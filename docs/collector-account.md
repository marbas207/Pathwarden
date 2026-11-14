# A least-privilege collector account

Since Windows 10 1607 and Server 2016, only local administrators can read a
computer's local groups remotely, so an ordinary account misses every local
admin path. This page sets up a collector account that can read local groups
and do nothing else: no sign-in, no admin rights, nothing on domain
controllers.

The grant is one security option, "Network access: Restrict clients allowed
to make remote calls to SAM", set by a GPO for one collector group.

## Set it up

You need rights to create and link GPOs, and the GroupPolicy and
ActiveDirectory PowerShell modules. Run the script from the release package,
`scripts\New-PathwardenCollectorGpo.ps1`, on the PDC emulator or in an
interactive session.

1. Create the collector account: a domain user, or a gMSA for a scheduled
   collection. It must not be in Tier Zero or a local admin anywhere.
2. Create a group that holds only that account, such as `Pathwarden
   Collectors`. The script accepts only a group created in a domain, refuses
   built-in and well-known groups, and warns above 10 members.
3. Check what the script would do, then run it:

   ```powershell
   .\New-PathwardenCollectorGpo.ps1 -CollectorGroup 'SCALE\Pathwarden Collectors' `
       -LinkTo 'OU=Servers,DC=scale,DC=local', 'OU=Workstations,DC=scale,DC=local' -WhatIf
   .\New-PathwardenCollectorGpo.ps1 -CollectorGroup 'SCALE\Pathwarden Collectors' `
       -LinkTo 'OU=Servers,DC=scale,DC=local', 'OU=Workstations,DC=scale,DC=local'
   ```

   It creates the GPO "Pathwarden collector access", denies domain
   controllers "Apply group policy" on it, and then links it. It prints the
   deny it reads back. It refuses an existing GPO it didn't create, one that holds
   other settings, or one others can change, and says why.
4. After the computers refresh policy (`gpupdate /force` on one to test),
   `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictRemoteSAM`
   ends with the collector group's SID.
5. Collect as the collector account with a **Full** collection. **Collection
   completeness** shows the share of computers whose local groups were read.

Computers still in the default `CN=Computers` container need a link at the
domain root (`-LinkTo 'DC=scale,DC=local'`). For several domains, run the
script once per domain with `-Domain`.

## Undo it

The setting stays on computers after the GPO is removed, so revert it first:

1. Run `.\New-PathwardenCollectorGpo.ps1 -CollectorGroup 'SCALE\Pathwarden Collectors' -Revert`.
2. After the computers refresh policy, check that `RestrictRemoteSAM` reads
   `O:BAG:BAD:(A;;RC;;;BA)`.
3. Delete the GPO.

## What it doesn't cover

Sessions still come mostly from Remote Registry on servers. A computer that
gets this option from another GPO with higher precedence keeps that value.

## Security

The group can read which accounts are local admin where, so keep the
collector account alone in it and protect its password.

### Delegation and Protected Users

- Mark the account "Account is sensitive and cannot be delegated"
  (`Set-ADUser svc-pathwarden -AccountNotDelegated $true`). The collector
  never needs delegation.
- Protected Users blocks NTLM, so the built-in collector's LDAP sign-in with
  a password fails for a member. Add a user account to Protected Users only
  if you collect as the current Windows user, and never a gMSA.
- With a password, computers are read with Kerberos AES256 only. An account whose password was
  set before the domain stored AES keys needs one password change.
