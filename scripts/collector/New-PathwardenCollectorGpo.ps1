<#
.SYNOPSIS
    Builds a GPO that lets a Pathwarden collector group read local group
    membership (remote SAM) on the computers it applies to.

.DESCRIPTION
    Windows 10 1607, Server 2016 and later allow remote SAM queries to local
    administrators only, so a collector running as an ordinary domain account
    can't see who is a local admin, RDP user or remote-management user on a
    host. This script creates one GPO (or updates the one it created) that
    sets the security option "Network access: Restrict clients allowed to
    make remote calls to SAM" to the Windows default (Administrators) plus
    read access for one collector group. Nothing else is granted: the group gets no logon right
    and no administrative access.

    Domain controllers never apply the GPO: it denies them "Apply group
    policy" (Domain Controllers, Read-only Domain Controllers and Enterprise
    Domain Controllers), wherever it is linked, and the script links it only
    once that deny is read back in place. That makes it safe to link at
    the domain root, which is the only way to reach computers left in the
    default Computers container (a container, not an OU, so GPOs can't be
    linked to it).

    The setting is a Security Option in the GPO's GptTmpl.inf, so it shows in
    the Group Policy Management Console like any other. Windows keeps security
    settings on a host after their GPO stops applying, so to undo it run this
    script again with -Revert, let it apply (gpupdate), and only then delete
    the GPO.

    It refuses an existing GPO with that name unless the script created it
    (the GPO's comment is the one the script sets), it holds only this
    setting, and only Domain Admins, Enterprise Admins, SYSTEM and
    Administrators own it or can change it. The refusal says why and changes
    nothing.

    The script changes only the GPO it names and the links it is given. Run it
    with -WhatIf first: it lists every step it would take (create the GPO,
    write the setting, raise the GPO's version, deny the domain controllers,
    each link) and changes nothing. It needs the GroupPolicy and
    ActiveDirectory modules (RSAT) and rights to create and link GPOs.

    It writes the GPO on the domain's PDC emulator, directory and SYSVOL
    alike, as GPMC does. Run it on the PDC emulator, or in an interactive
    session on any computer: from a remote session (WinRM) to another
    domain controller, reaching the PDC emulator is a second hop and fails
    without CredSSP.

    When it has run, it prints the GPO's name and GUID, the value it sets, its
    links in the domain, and the domain-controller deny as read back from the
    GPO's directory object. Get-GPPermission doesn't list deny entries, so it
    can't be used to check the deny.

    See docs/collector-account.md.

.PARAMETER CollectorGroup
    The group the collector account is a member of: DOMAIN\Group, or a SID.
    It may be in another domain or a trusted forest. It must be a group
    created in a domain: built-in and well-known groups are refused. The
    script warns if it has more than 10 members.

.PARAMETER Name
    The GPO's name. Default: "Pathwarden collector access".

.PARAMETER LinkTo
    Distinguished names of the OUs to link the GPO to (servers, workstations),
    or the domain's own distinguished name to link it at the domain root. Not
    the Domain Controllers OU: domain controllers' groups are read from the
    directory, and on a domain controller this setting controls remote access
    to the domain's own accounts database.

.PARAMETER Domain
    The domain to create the GPO in. Default: the current user's domain.

.PARAMETER Revert
    Set the option back to the Windows default (Administrators only) in the
    same GPO, keeping its links, so that hosts drop the grant at their next
    policy refresh. The GPO must exist.

.EXAMPLE
    .\New-PathwardenCollectorGpo.ps1 -CollectorGroup 'CONTOSO\Pathwarden Collectors' -LinkTo 'OU=Servers,DC=contoso,DC=local' -WhatIf

.EXAMPLE
    .\New-PathwardenCollectorGpo.ps1 -CollectorGroup 'CONTOSO\Pathwarden Collectors' -LinkTo 'DC=contoso,DC=local'

    Links at the domain root, to reach computers in the default Computers
    container. Domain controllers are excluded by the GPO's permissions.

.EXAMPLE
    .\New-PathwardenCollectorGpo.ps1 -CollectorGroup 'CONTOSO\Pathwarden Collectors' -Revert
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$CollectorGroup,
    [string]$Name = 'Pathwarden collector access',
    [string[]]$LinkTo = @(),
    [string]$Domain,
    [switch]$Revert
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy, ActiveDirectory -ErrorAction Stop

# Windows' default for the option: Administrators may read.
$DefaultSddl = 'O:BAG:BAD:(A;;RC;;;BA)'
# The Security (SCE) client-side extension and its editor, as GPMC writes them.
$SecurityExtensions = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
# The "Apply group policy" extended right on a GPO's directory object.
$ApplyGroupPolicy = [guid]'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
# The comment the script gives a GPO it creates. An existing GPO with -Name is
# changed only if its comment is this one (see Assert-OwnGpo).
$Marker = 'Pathwarden: remote SAM read for the collector group. See docs/collector-account.md.'

function Resolve-Sid([string]$Principal) {
    if ($Principal -match '^S-1-[0-9-]+$') {
        return (New-Object System.Security.Principal.SecurityIdentifier($Principal)).Value
    }
    $account = New-Object System.Security.Principal.NTAccount($Principal)
    return $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
}

# The GPO's directory object (GPC), opened to read or change its DACL.
# -WithOwner also reads the owner; such an entry is only read, never
# committed (a commit would write the owner back too).
function Open-Gpc([string]$Server, [string]$Dn, [switch]$WithOwner) {
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$Dn")
    # psbase: PowerShell shows a directory entry's LDAP attributes as its
    # properties, so .Options would be the object's 'options' attribute.
    $masks = [System.DirectoryServices.SecurityMasks]::Dacl
    if ($WithOwner) { $masks = $masks -bor [System.DirectoryServices.SecurityMasks]::Owner }
    $entry.psbase.Options.SecurityMasks = $masks
    return , $entry
}

# A SID with its account name, when it resolves.
function Format-Sid([string]$Sid) {
    try {
        $account = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
        return "$account ($Sid)"
    } catch {
        return $Sid
    }
}

# The lines of an existing GptTmpl.inf other than the ones this script
# writes. Empty when the file holds only the script's setting.
function Get-ForeignInfLine([string]$Path) {
    $allowed = @{
        'unicode'         = @('unicode')
        'version'         = @('signature', 'revision')
        'registry values' = @('machine\system\currentcontrolset\control\lsa\restrictremotesam')
    }
    $section = $null
    $foreign = @()
    foreach ($raw in (Get-Content -LiteralPath $Path)) {
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith(';')) { continue }
        if ($line -match '^\[(.+)\]$') {
            $section = $Matches[1].Trim()
            if (-not $allowed.ContainsKey($section.ToLower())) { $foreign += "[$section]" }
            continue
        }
        $key = ($line -split '=', 2)[0].Trim().ToLower()
        if (-not $section) {
            $foreign += $line
        } elseif ($allowed.ContainsKey($section.ToLower()) -and $allowed[$section.ToLower()] -notcontains $key) {
            $foreign += "[$section] $line"
        }
    }
    return $foreign
}

# Refuse a GPO with -Name that this script didn't create, holds other
# settings, or can be changed by others than the domain's admins: the script
# would overwrite its settings, or someone else could change the grant after
# it is written.
function Assert-OwnGpo($Gpo, [string]$GpcDn, [string]$Gpt, [string]$Inf) {
    $what = "GPO '$($Gpo.DisplayName)' ($('{' + $Gpo.Id.ToString().ToUpper() + '}')) in $Domain"
    $choose = "Pick another -Name, or check that GPO and delete it if nothing needs it."

    # 1. The comment the script sets when it creates the GPO.
    if ($Gpo.Description -ne $Marker) {
        throw "$what already exists and this script didn't create it: its comment isn't the one the script sets. Not changing it, because the script would overwrite its security settings and links. $choose"
    }

    # 2. Only the Security settings, on the computer side.
    $gpc = Get-ADObject -Identity $GpcDn -Server $server -Properties gPCMachineExtensionNames, gPCUserExtensionNames
    # An unset attribute may be missing from the object (strict mode).
    $machineExt = if ($gpc.PSObject.Properties['gPCMachineExtensionNames']) { [string]$gpc.gPCMachineExtensionNames } else { '' }
    $userExt = if ($gpc.PSObject.Properties['gPCUserExtensionNames']) { [string]$gpc.gPCUserExtensionNames } else { '' }
    $other = @()
    if ($machineExt -and $machineExt -ne $SecurityExtensions) { $other += "computer settings $machineExt" }
    if ($userExt) { $other += "user settings $userExt" }
    if ($other.Count -gt 0) {
        throw "$what holds settings this script doesn't write ($($other -join '; ')). Not changing it, because the script would drop them. $choose"
    }
    if (Test-Path -LiteralPath $Inf) {
        $foreign = @(Get-ForeignInfLine $Inf)
        if ($foreign.Count -gt 0) {
            throw "$Inf holds settings this script doesn't write: $($foreign -join '; '). Not overwriting it. $choose"
        }
    }

    # 3. Owner and editors: only Domain Admins, Enterprise Admins, SYSTEM and
    # the built-in Administrators.
    $forest = Get-ADForest -Server $server
    $rootSid = if ($forest.RootDomain -eq $adDomain.DNSRoot) { $adDomain.DomainSID.Value } else { (Get-ADDomain -Identity $forest.RootDomain -Server $forest.RootDomain).DomainSID.Value }
    $admins = @("$($adDomain.DomainSID.Value)-512", "$rootSid-519", 'S-1-5-18', 'S-1-5-32-544')

    # Schema GUIDs of the GPO's class and of the attributes that decide what
    # it does: a write to another attribute (msDS-KeyCredentialLink for Key
    # Admins, inherited from the domain root) doesn't change the GPO.
    $schemaNc = (Get-ADRootDSE -Server $server).schemaNamingContext
    $names = @('groupPolicyContainer', 'versionNumber', 'gPCFileSysPath', 'gPCMachineExtensionNames', 'gPCUserExtensionNames', 'gPCFunctionalityVersion', 'gPCWQLFilter', 'flags')
    $filter = '(|' + (($names | ForEach-Object { "(lDAPDisplayName=$_)" }) -join '') + ')'
    $gpcClass = [guid]::Empty
    $gpoAttributes = @()
    foreach ($s in (Get-ADObject -SearchBase $schemaNc -LDAPFilter $filter -Server $server -Properties lDAPDisplayName, schemaIDGUID)) {
        $id = New-Object System.Guid (, [byte[]]$s.schemaIDGUID)
        if ($s.lDAPDisplayName -eq 'groupPolicyContainer') { $gpcClass = $id } else { $gpoAttributes += $id }
    }

    $editors = @()
    $read = Open-Gpc $server $GpcDn -WithOwner
    $security = $read.psbase.ObjectSecurity
    $owner = $security.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($admins -notcontains $owner) { $editors += "owner $(Format-Sid $owner)" }
    $R = [System.DirectoryServices.ActiveDirectoryRights]
    foreach ($rule in $security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($rule.InheritedObjectType -ne [guid]::Empty -and $rule.InheritedObjectType -ne $gpcClass) { continue }
        $rights = $rule.ActiveDirectoryRights
        $edits = ($rights -band ($R::WriteDacl -bor $R::WriteOwner -bor $R::CreateChild)) -or
            (($rights -band $R::WriteProperty) -and ($rule.ObjectType -eq [guid]::Empty -or $gpoAttributes -contains $rule.ObjectType))
        $who = $rule.IdentityReference.Value
        if ($edits -and $admins -notcontains $who) { $editors += "$(Format-Sid $who) in the directory" }
    }

    # The GPO's SYSVOL folder: its owner and the rights set on it (rights it
    # inherits from the Policies folder are the same for every GPO).
    $acl = Get-Acl -LiteralPath $Gpt
    $folderOwner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($admins -notcontains $folderOwner) { $editors += "owner of $Gpt $(Format-Sid $folderOwner)" }
    # Write, append, attributes, delete, change permissions, take ownership,
    # and the generic write and all rights.
    $fileWrite = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
    foreach ($rule in $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        $who = $rule.IdentityReference.Value
        if (([int64]$rule.FileSystemRights -band $fileWrite) -and $admins -notcontains $who) { $editors += "$(Format-Sid $who) on SYSVOL" }
    }

    if ($editors.Count -gt 0) {
        $list = ($editors | Select-Object -Unique) -join '; '
        throw "$what can be changed by accounts other than Domain Admins, Enterprise Admins, SYSTEM and Administrators: $list. Not changing it, because they could change the grant after the script writes it. Remove those rights (Group Policy Management Console, Delegation, Advanced), or pick another -Name."
    }
}

# The SIDs the GPC's own (not inherited) DACL denies "Apply group policy".
function Get-ApplyDenied($Entry) {
    $Entry.psbase.ObjectSecurity.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object {
            $_.AccessControlType -eq 'Deny' -and $_.ObjectType -eq $ApplyGroupPolicy -and
            ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)
        } |
        ForEach-Object { $_.IdentityReference.Value }
}

if (-not $Domain) { $Domain = (Get-ADDomain).DNSRoot }
$adDomain = Get-ADDomain -Identity $Domain
# The GroupPolicy cmdlets work on the PDC emulator. Read and write the GPO's
# directory object and its SYSVOL folder there too (as GPMC does), so that a
# GPO created a moment ago is found, the two halves of its version stay
# together, and the read-back at the end sees the change just made.
$server = $adDomain.PDCEmulator

$sid = Resolve-Sid $CollectorGroup
# A grant to everyone, to every user or to every computer would let any
# account list every host's administrators. Accept only a group created in a
# domain (S-1-5-21-..., RID 1000 or more): that rules out every well-known
# and built-in group (Everyone, Authenticated Users, NETWORK, INTERACTIVE,
# This Organization, Users, Guests, Domain Users, Domain Guests, Domain
# Computers and the rest), without a list that can miss one.
if (-not ($sid -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$' -and [int64]$Matches[1] -ge 1000)) {
    throw "$CollectorGroup ($sid) is a built-in or well-known group, and those are too broad. Create a domain group that holds only the collector account, and pass that."
}
# A big group is allowed, but every member can list every host's
# administrators. Members are counted only for a group in this domain.
$groupDomainSid = $sid -replace '-\d+$', ''
if ($groupDomainSid -eq $adDomain.DomainSID.Value) {
    try {
        $memberCount = @(Get-ADGroupMember -Identity $sid -Recursive -Server $server).Count
        if ($memberCount -gt 10) {
            Write-Warning "$CollectorGroup has $memberCount members. Each of them will be able to list every computer's local administrators: keep only the collector account in it."
        }
    } catch {
        Write-Verbose "Couldn't count the members of $CollectorGroup`: $($_.Exception.Message)"
    }
}

foreach ($ou in $LinkTo) {
    if ($ou -match '^OU=Domain Controllers,') {
        throw "Not linking to $ou`: domain controllers' groups are read from the directory, and there this option controls remote access to the domain's accounts."
    }
    if ($ou -ne $adDomain.DistinguishedName) {
        $null = Get-ADOrganizationalUnit -Identity $ou -Server $server
    }
}

$sddl = if ($Revert) { $DefaultSddl } else { "$DefaultSddl(A;;RC;;;$sid)" }
$option = "'Network access: Restrict clients allowed to make remote calls to SAM'"
$gpoTarget = "GPO '$Name'"
$domainControllers = @(
    @{ Sid = "$($adDomain.DomainSID.Value)-516"; Name = 'Domain Controllers' },
    @{ Sid = "$($adDomain.DomainSID.Value)-521"; Name = 'Read-only Domain Controllers' },
    @{ Sid = 'S-1-5-9'; Name = 'Enterprise Domain Controllers' }
)

# -Confirm makes every cmdlet the script calls ask again inside its own
# prompt; declining one of those would leave a half-done step. Each step is
# confirmed once, by ShouldProcess, so the cmdlets inside it don't ask.
function Get-NoConfirm([string]$Command) {
    if ((Get-Command $Command).Parameters.ContainsKey('Confirm')) { return @{ Confirm = $false } }
    return @{}
}
$newGpoNoConfirm = Get-NoConfirm 'New-GPO'
$newGpLinkNoConfirm = Get-NoConfirm 'New-GPLink'

# Each step below asks ShouldProcess, so -WhatIf lists all of them. With
# -WhatIf on a first run there is no GPO yet ($gpo stays $null): every step is
# then only described, never run, and nothing may read $gpo's properties.
$gpo = Get-GPO -Name $Name -Domain $Domain -ErrorAction SilentlyContinue
$created = $false
if (-not $gpo) {
    if ($Revert) { throw "No GPO named '$Name' in ${Domain}: nothing to revert." }
    if ($PSCmdlet.ShouldProcess($Domain, "Create GPO '$Name'")) {
        $gpo = New-GPO -Name $Name -Domain $Domain -Comment $Marker @newGpoNoConfirm
        if (-not $gpo) { throw "New-GPO did not create '$Name' in $Domain." }
        $created = $true
    } elseif (-not $WhatIfPreference) {
        # Declined at a -Confirm prompt: the other steps need the GPO.
        Write-Host "GPO '$Name' not created; nothing changed."
        return
    }
}

$guid = $null; $gpt = $null; $secEdit = $null; $inf = $null; $gpcDn = $null
if ($gpo) {
    $guid = '{' + $gpo.Id.ToString().ToUpper() + '}'
    $gpt = "\\$server\SYSVOL\$Domain\Policies\$guid"
    $secEdit = Join-Path $gpt 'Machine\Microsoft\Windows NT\SecEdit'
    $inf = Join-Path $secEdit 'GptTmpl.inf'
    $gpcDn = "CN=$guid,CN=Policies,CN=System,$($adDomain.DistinguishedName)"
    # Only reads, so -WhatIf refuses the same GPOs a real run would.
    if (-not $created) { Assert-OwnGpo $gpo $gpcDn $gpt $inf }
}

$content = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM=1,"$sddl"
"@

if ($PSCmdlet.ShouldProcess($gpoTarget, "Write GptTmpl.inf setting $option to $sddl")) {
    $null = New-Item -ItemType Directory -Force -Path $secEdit -Confirm:$false
    # GPMC writes GptTmpl.inf as UTF-16 LE with a byte order mark.
    Set-Content -LiteralPath $inf -Value $content -Encoding Unicode -Confirm:$false
}

# Raise the computer half (low 16 bits) of the version, in the directory and
# in GPT.ini, so that clients apply the change.
if ($PSCmdlet.ShouldProcess($gpoTarget, "Raise the computer version (directory and GPT.INI) so that computers apply the change")) {
    $gpc = Get-ADObject -Identity $gpcDn -Server $server -Properties versionNumber
    $version = [int]$gpc.versionNumber
    $computer = ($version -band 0xFFFF) + 1
    if ($computer -gt 0xFFFF) { $computer = 1 }
    $version = ($version -band 0xFFFF0000) -bor $computer
    Set-ADObject -Identity $gpcDn -Server $server -Confirm:$false -Replace @{
        versionNumber            = $version
        gPCMachineExtensionNames = $SecurityExtensions
    }
    Set-Content -LiteralPath (Join-Path $gpt 'GPT.INI') -Value "[General]`r`nVersion=$version" -Encoding Ascii -Confirm:$false
}

# Deny "Apply group policy" to every domain controller, so that a link at the
# domain root (or an OU a domain controller is later moved into) never applies
# the setting to one.
$entry = $null
$denied = @()
if ($gpo) {
    $entry = Open-Gpc $server $gpcDn
    $denied = @(Get-ApplyDenied $entry)
}
$missing = @($domainControllers | Where-Object { $denied -notcontains $_.Sid })
# The GPO is linked only once the deny is in place: a link without it would
# apply the setting to domain controllers.
$denyOk = $false
if ($missing.Count -eq 0) {
    Write-Verbose "The domain controllers are already denied 'Apply group policy'."
    $denyOk = $true
} elseif ($PSCmdlet.ShouldProcess($gpoTarget, "Deny 'Apply group policy' to " + (($missing | ForEach-Object { "$($_.Name) ($($_.Sid))" }) -join ', '))) {
    $security = $entry.psbase.ObjectSecurity
    foreach ($dc in $missing) {
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($dc.Sid)),
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Deny,
            $ApplyGroupPolicy)
        $security.AddAccessRule($rule)
    }
    $entry.psbase.CommitChanges()
    # Read it back from the directory: a commit that wrote nothing must not
    # be taken for a deny.
    $denied = @(Get-ApplyDenied (Open-Gpc $server $gpcDn))
    $stillMissing = @($domainControllers | Where-Object { $denied -notcontains $_.Sid } | ForEach-Object { "$($_.Name) ($($_.Sid))" })
    if ($stillMissing.Count -gt 0) {
        throw "The deny of 'Apply group policy' did not reach $gpcDn for: $($stillMissing -join ', '). Nothing was linked. Add the deny in the Group Policy Management Console (Delegation, Advanced) or run the script again."
    }
    $denyOk = $true
}

foreach ($ou in $LinkTo) {
    $linked = $null
    if ($gpo) {
        $linked = (Get-GPInheritance -Target $ou -Domain $Domain).GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }
    }
    if ($linked) {
        Write-Verbose "Already linked to $ou."
    } elseif (-not $denyOk -and -not $WhatIfPreference) {
        Write-Host "Not linking to ${ou}: domain controllers are not denied 'Apply group policy' on this GPO." -ForegroundColor Yellow
    } elseif ($PSCmdlet.ShouldProcess($ou, "Link GPO '$Name' (enabled)")) {
        $null = New-GPLink -Guid $gpo.Id -Target $ou -Domain $Domain -LinkEnabled Yes @newGpLinkNoConfirm
    }
}

if ($WhatIfPreference) {
    Write-Host 'No changes made (-WhatIf).'
    return
}

# Summary, read back from the GPO rather than from what was asked for.
$setTo = $null
if (Test-Path -LiteralPath $inf) {
    $line = Get-Content -LiteralPath $inf | Where-Object { $_ -match 'RestrictRemoteSAM=1,"([^"]*)"' } | Select-Object -First 1
    if ($line -and $line -match 'RestrictRemoteSAM=1,"([^"]*)"') { $setTo = $Matches[1] }
}
Write-Host ''
Write-Host "GPO    $Name $guid in $Domain"
if ($setTo) {
    Write-Host "Sets   $option to $setTo"
} else {
    Write-Host "Sets   nothing yet: GptTmpl.inf has no $option" -ForegroundColor Yellow
}
if ($setTo -and $setTo -ne $sddl) {
    Write-Warning "GptTmpl.inf sets $setTo, not $sddl."
}

# Links in this domain (the domain root and OUs), from their gPLink attribute:
# option bit 1 = link disabled, bit 2 = enforced.
$links = @(Get-ADObject -LDAPFilter "(&(|(objectCategory=organizationalUnit)(objectCategory=domainDNS))(gPLink=*$guid*))" -Server $server -Properties gPLink)
$linkPattern = '(?i)\[LDAP://cn=' + [regex]::Escape($guid) + ',[^;\]]*;(\d+)\]'
$shown = 0
foreach ($target in $links) {
    if ($target.gPLink -match $linkPattern) {
        $flags = [int]$Matches[1]
        $state = if ($flags -band 1) { 'disabled' } else { 'enabled' }
        if ($flags -band 2) { $state += ', enforced' }
        Write-Host "Link   $($target.DistinguishedName) ($state)"
        $shown++
    }
}
if ($shown -eq 0) {
    Write-Host "Link   none: link it to the OUs of the servers and workstations to collect, or to the domain root ($($adDomain.DistinguishedName)) to reach the Computers container."
}

# The deny, read back from the GPC object's DACL. Get-GPPermission doesn't
# list deny entries, so it can't confirm this.
$denied = @(Get-ApplyDenied (Open-Gpc $server $gpcDn))
$notDenied = @()
Write-Host 'Domain controllers (read back from the GPO object''s permissions):'
foreach ($dc in $domainControllers) {
    if ($denied -contains $dc.Sid) {
        Write-Host "       $($dc.Name) ($($dc.Sid)): denied: Apply group policy"
    } else {
        Write-Host "       $($dc.Name) ($($dc.Sid)): NOT DENIED" -ForegroundColor Red
        $notDenied += $dc.Name
    }
}
if ($notDenied.Count -gt 0) {
    Write-Warning ("NOT denied 'Apply group policy': " + ($notDenied -join ', ') + ". Domain controllers in these groups apply this GPO wherever it is linked, including at the domain root. Run the script again, or add the deny in the Group Policy Management Console (Delegation, Advanced), before computers refresh policy.")
}

Write-Host ''
if ($setTo -ne $sddl) {
    Write-Host "GPO '$Name' does not set $sddl (see above): run the script again." -ForegroundColor Yellow
} elseif ($Revert) {
    Write-Host "GPO '$Name' now sets the Windows default ($DefaultSddl)."
    Write-Host "After the hosts have refreshed policy (gpupdate /force, or up to 90 minutes), delete it: Remove-GPO -Name '$Name' -Domain $Domain"
} else {
    Write-Host "GPO '$Name' grants $CollectorGroup ($sid) remote SAM read."
    Write-Host "On a host it applies to, check after gpupdate /force:"
    Write-Host "  reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictRemoteSAM"
}
