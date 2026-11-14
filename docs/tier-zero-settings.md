# Tier Zero settings (DCs and CAs)

ESC9 and ESC10 need two registry values on every domain controller, and
ESC6 and ESC11 two on every certification authority (CA). Only an
administrator of those servers can read them. A read-only script reads them
on each server and writes a small file that Pathwarden analyzes with the
collection, so the collection account needs no admin rights there.

Without the files, PW-020 findings say "(unverified)" and ESC6 and ESC11
are "not checked". Run the script when the run's **Tier Zero settings** row
asks for it, after you patch the DCs or change a value, and at least every
90 days.

## Run the script

On each domain controller and each CA, in an elevated PowerShell:

```powershell
.\Get-PathwardenTierZeroSettings.ps1 -OutputDirectory C:\Temp
```

The script is in `scripts\` in the release and changes nothing. It writes
`pathwarden-tierzero-<HOST>.<domain>.json`. With admin rights and Remote
Registry, `-AllDomainControllers -AllCertificationAuthorities` reads every
server over the network.

Put the files in the collection folder or zip, give them with `-i`, or
save them to a settings folder.

## Settings folders

A settings folder is a share where the servers save their files, for
example from a scheduled task on each DC and CA that runs the script as
SYSTEM. Every analysis of the environment reads it.

### In the app

1. In the rail, click **Settings**.
2. Under **Tier Zero settings folders**, add the folder.

On another computer, a folder from the shared settings shows "From the
repository. Not used here yet." Click **Use** to read it there.

### On the command line

    pathwarden config settings-folders add \\dc01.scale.local\pathwarden-t0
    pathwarden config settings-folders use \\dc01.scale.local\pathwarden-t0

### Make the folder trusted

A file in a folder can only clear a weakness when the server itself or a
Tier Zero account wrote it and nobody else can change it. Otherwise it can
still show a weakness.

1. Host the folder on a domain controller, or on the server whose files it
   holds.
2. Run the script as SYSTEM on each server.
3. Give the folder this ACL, with one line per DC and CA computer account:

```powershell
icacls D:\pathwarden-t0 /inheritance:r `
  /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" "SCALE\Domain Admins:(OI)(CI)F" `
  /grant:r "SCALE\DC01$:(OI)(CI)(WD,AD,RD,RA,REA,X)" "SCALE\PKI01$:(OI)(CI)(WD,AD,RD,RA,REA,X)" `
  /grant:r "CREATOR OWNER:(OI)(CI)(IO)F" `
  /grant:r "SCALE\Pathwarden readers:(OI)(CI)RX"
```

4. Name the file server by its full DNS name, not a DFS namespace.

## What it reads

On a DC, `StrongCertificateBindingEnforcement` and
`CertificateMappingMethods`. On a CA, `EditFlags` and `InterfaceFlags`. It
reads no secrets. One weak DC opens the path; closing it needs a strong
value on every DC of the forest.

### Management agents

The script also records the management agents on each DC and CA: SCCM,
SCOM, WSUS, Hyper-V or VMware guest, OpenSSH server, and backup agents.
Whoever controls their servers can run code on the host, so those servers
are Tier Zero too ([Management planes](rules.md#management-planes)).

## Unset values and the OS build

Windows update KB5014754 changed what an unset value means. Pathwarden uses
the OS build the script records for Windows Server 2016 to 2025. Without a
build (SharpHound data has none), an unset value stays unverified. Setting
the values explicitly (binding 2, mapping 0x18) gives a clear answer on any
build.

## What can go wrong

| Problem | Fix |
|---|---|
| "Access is denied" when the collection reads DC values. | Expected for a plain collection account. Run the script on the servers. |
| ESC9 or ESC10 stays unverified. | Run the script on every DC of the forest. |
| A file is stale. | It was read more than 90 days before the collection. Run the script again. |
| A folder's file doesn't clear a finding. | Follow [Make the folder trusted](#make-the-folder-trusted). |
| A folder isn't read. | Choose **Use** for it on **Settings**. |
| A file is listed under skipped files. | Its server isn't in the collection. Run the script on the right server. |
