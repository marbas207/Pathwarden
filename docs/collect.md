# Collecting Active Directory data

Pathwarden reads your directory and writes BloodHound CE data that every
analysis command loads.

## Before you start

- Only collect from domains you are authorized to assess. Store the
  collection like credentials.
- Use a computer that reaches a domain controller on TCP 389 or 636, and 88.
  A Full collection also needs TCP 445 to every computer.
- Use an ordinary domain account, never a Domain Admin. For local groups
  without local admin rights, set up [a collector account](collector-account.md).

## Collect

In the app, follow [Collect from Active Directory](tasks.md#collect-from-active-directory).

### On the command line

```powershell
pathwarden collect --domain scale.local --output C:\Temp\collect --save
```

`--save` analyzes and saves the run, as the app does. Use an empty
`--output` folder each time. `pathwarden collect --help` lists every option.

**Quick** (`--scope dc-only`, the default) reads the directory in minutes.
**Full** (`--scope all`) also reads sessions and local groups from every
computer; it takes longer and EDR may flag it. Without it, paths through
logged-on admins and local admin rights are missing.

| Method | Option | Runs on |
|---|---|---|
| Built-in (default) | none | Windows, Linux. |
| SharpHound | `--sharphound PATH` | Windows, as your Windows account. |
| RustHound-CE | `--rusthound PATH --kerberos [CCACHE]` | Windows, Linux, with a Kerberos ticket cache. |

## Signing in

- **Your Windows account** works on a domain-joined computer and for a
  gMSA. With the built-in collector it is Quick only.
- **A user and password** (`--user`, with `--ldaps`) works on Linux and for
  a built-in Full collection. The password comes from
  `PATHWARDEN_COLLECT_PASSWORD` or a prompt.
- Name the domain controller by its full name (`--server
  dc01.contoso.local`, or **Domain controller** on the Collect page), not
  an IP address. Results are only trustworthy then: without it DNS picks
  the domain controller, and a spoofed one could return a clean directory
  and mark findings fixed. The run warns when it wasn't named. The full
  name also makes the LDAPS certificate match.

### From a computer outside the domain

**Use my Windows account** needs a domain account. On a computer that
isn't in the domain, either enter a user and password, or start Pathwarden
as a domain user for network sign-ins only:

```powershell
runas /netonly /user:SCALE\svc-pathwarden "C:\Pathwarden\pathwarden.exe ui"
```

Then choose **Use my Windows account**. The computer must reach the
domain's DNS and a domain controller.

### Signing in to computers

The built-in collector signs in to computers with **Kerberos only** and
**Require SMB signing**. A computer that can't do both is skipped and counts
as not collected. Leave both on: NTLM sign-ins can be relayed. Kerberos
needs this computer's clock within 5 minutes of the domain's.
`--allow-ntlm` and `--allow-unsigned-smb` turn them off.

## What each method collects

| | Built-in, Windows account | Built-in, `--user` | Built-in, `--user --scope all` | SharpHound (Full) |
|---|---|---|---|---|
| Users, groups, computers, GPOs, trusts, ACLs, AD CS | Yes. | Yes. | Yes. | Yes. |
| CA registry flags (ESC6, ESC11) | No. | No. | Yes. | ESC6 only. |
| Rights set by Group Policy | No. | Yes. | Yes. | Yes. |
| GPP passwords in SYSVOL (PW-026) | Yes. | Yes. | Yes. | No. |
| GPO folder and logon script permissions (PW-027) | Yes. | No. | No. | No. |
| Sessions | No. | No. | Yes. | Yes. |
| Local groups | No. | No. | Yes, as a local admin or with [the collector account](collector-account.md). | Yes. |
| Accounts services and tasks run as (PW-033) | No. | No. | Yes, as a local admin. | No. |

A computer that wasn't read counts as not collected, and findings that
depend on it are **Can't tell**. For ESC9 and ESC10, see
[Tier Zero settings](tier-zero-settings.md).

## Trusted domains

For paths that cross trusts, collect the trusted domains in the same run:
tick them under **Trusted domains** on **Where**, or give `--domain` again.
A domain that fails is skipped.

## Run it on a schedule

See [Run on a schedule](running.md#run-on-a-schedule). On Windows the task
runs as a gMSA; on Linux, as a dedicated user with the password in a
systemd credential, never in the unit or a script.

## When something goes wrong

| Message | What to do |
|---|---|
| Couldn't find a domain controller. | Check the domain's spelling and that this computer uses the domain's DNS. |
| Couldn't reach a domain controller. | Open TCP 389 or 636 from this computer, or check the VPN. |
| The domain controller's certificate wasn't accepted. | Use its full name. The issuing CA must be in this computer's trusted roots. |
| The sign-in was refused. | Check the user name and password, and that the account isn't locked or expired. |
| The domain controller requires LDAP signing. | Turn on LDAPS. |
| Kerberos didn't work. | Check this computer's clock and TCP 88 to the domain controller. |
| The collection stopped. | Within 24 hours, click **Resume** on **Collect**, or run the same command with `--resume`. |
| The domain controller is busy. | Lower the parallel reads with `--read-streams 2`. |
