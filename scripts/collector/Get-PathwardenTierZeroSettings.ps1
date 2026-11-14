<#
.SYNOPSIS
    Reads the domain controller and certification authority registry values
    that decide ESC6, ESC9, ESC10 and ESC11, and writes them to a file for
    Pathwarden. Read-only.

.DESCRIPTION
    ESC9 and ESC10 (AD CS certificate mapping abuse) depend on two registry
    values on every domain controller; ESC6 and ESC11 on two registry values
    of every certification authority. Reading them from another computer
    needs admin rights there, and a collection account should not have
    those. So the servers' own admins run this script on each domain
    controller and each certification authority instead, and give its file
    to whoever runs Pathwarden (or save it to a shared settings folder that
    Pathwarden reads). Pathwarden then shows these as verified attack paths,
    or closes them, instead of "unverified".

    On a domain controller it reads these values from HKLM:

      SYSTEM\CurrentControlSet\Services\Kdc
          StrongCertificateBindingEnforcement   (ESC9, ESC10)
      SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel
          CertificateMappingMethods             (ESC10)
      SYSTEM\CurrentControlSet\Services\NTDS\Parameters
          LDAPServerIntegrity                   (LDAP signing)
          LdapEnforceChannelBinding             (LDAP channel binding)
      SYSTEM\CurrentControlSet\Control\Lsa
          LmCompatibilityLevel                  (NTLM versions accepted)

    On a certification authority (where
    SYSTEM\CurrentControlSet\Services\CertSvc\Configuration names an active
    CA) it reads, for that CA:

      ...\Configuration\<CA>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy
          EditFlags                             (ESC6: the SAN flag)
      ...\Configuration\<CA>
          InterfaceFlags                        (ESC11: encrypted requests)
          RoleSeparationEnabled                 (recorded only)
          CACertHash                            (matches the CA to its AD object)

    On every domain controller and certification authority host it also
    reads which management agents run there (schema v2): whoever controls
    their servers can run code on the host, so those servers are Tier Zero
    too. Presence and names only:

      SOFTWARE\Microsoft\CCM                    (SCCM client)
      SOFTWARE\Microsoft\SMS\Mobile Client
          AssignedSiteCode                      (its SCCM site)
      SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Agent Management Groups
          <group>\Parent Health Services\<n>
          NetworkName                           (its SCOM management servers)
      SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
          WUServer, WUStatusServer, AU\UseWUServer (its WSUS server)
      SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters
          PhysicalHostNameFullyQualified        (its Hyper-V host)
      SOFTWARE\VMware, Inc.\VMware Tools        (a VMware virtual machine)
      SYSTEM\CurrentControlSet\Services\sshd    (an OpenSSH server)
      SYSTEM\CurrentControlSet\Services\<name>  (backup agents: Veeam,
                                                 Commvault, NetBackup, DPM)

    It also records the domain, the computer's host and DNS names, its
    account SID and distinguished name when Windows has them locally, the OS
    build (the defaults of values that are not set depend on the patch
    level), and the time it read them (UTC). It reads no secrets and no
    account names.

    It changes nothing, needs no modules, and makes no network connection:
    everything is read from the local registry, WMI and the local security
    authority. Run it in an elevated PowerShell (Windows PowerShell 5.1 or
    later) on each domain controller and each certification authority.

    It writes pathwarden-tierzero-<HOST>.<domain>.json to -OutputDirectory
    (the current folder by default) and prints what it read. Put the files
    beside the collection you load into Pathwarden (in its folder, or in its
    zip), or in a Tier Zero settings folder (Settings in the app). Run it
    again after patching or changing these settings: a file read more than
    90 days before the collection is stale, and Pathwarden then uses it only
    to show weaknesses, never to clear them.

    See docs/tier-zero-settings.md.

.PARAMETER OutputDirectory
    The folder to write the file to. Default: the current folder.

.PARAMETER AllDomainControllers
    Read every domain controller of this computer's domain instead, over the
    network (remote registry), writing one file per domain controller. This
    needs admin rights on each of them and the Remote Registry service
    running there. Optional; by default only the local computer is read.

.PARAMETER AllCertificationAuthorities
    Read every certification authority of the forest instead (the hosts
    listed under CN=Enrollment Services), over the network (remote
    registry), writing one file per host. The same needs as
    -AllDomainControllers. With both, a host that is both is read once.

.EXAMPLE
    .\Get-PathwardenTierZeroSettings.ps1

    On a domain controller or a CA: writes .\pathwarden-tierzero-<HOST>.<domain>.json.

.EXAMPLE
    .\Get-PathwardenTierZeroSettings.ps1 -OutputDirectory \\fs01\pathwarden-t0

.EXAMPLE
    .\Get-PathwardenTierZeroSettings.ps1 -AllDomainControllers -AllCertificationAuthorities -OutputDirectory C:\Temp
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Get-Location).ProviderPath,
    [switch]$AllDomainControllers,
    [switch]$AllCertificationAuthorities
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Schema = 'pathwarden.tierzero.v2'
# What is read on a domain controller: the registry key under HKLM and the
# value name.
$Wanted = @(
    @{ Key = 'SYSTEM\CurrentControlSet\Services\Kdc'; Name = 'StrongCertificateBindingEnforcement' },
    @{ Key = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel'; Name = 'CertificateMappingMethods' },
    @{ Key = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Name = 'LDAPServerIntegrity' },
    @{ Key = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Name = 'LdapEnforceChannelBinding' },
    @{ Key = 'SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel' }
)
# Where a certification authority keeps its configuration.
$CertSvc = 'SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$PolicyModule = 'PolicyModules\CertificateAuthority_MicrosoftDefault.Policy'

# One value: present or not, its number, or why it could not be read.
function Read-Value($Hklm, [string]$Key, [string]$Name) {
    $out = [ordered]@{
        name    = $Name
        path    = "HKLM\$Key"
        present = $false
        value   = $null
        error   = $null
    }
    try {
        $sub = $Hklm.OpenSubKey($Key, $false)
        if ($null -eq $sub) {
            return $out
        }
        try {
            $data = $sub.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -eq $data) {
                return $out
            }
            $out.present = $true
            $kind = $sub.GetValueKind($Name)
            if ($kind -eq [Microsoft.Win32.RegistryValueKind]::DWord) {
                # A DWORD comes back signed; keep it unsigned, as regedit shows it.
                $out.value = [int64][BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$data), 0)
            } elseif ($kind -eq [Microsoft.Win32.RegistryValueKind]::QWord) {
                $out.value = [int64]$data
            } else {
                $out.error = "not a number (type $kind)"
            }
        } finally {
            $sub.Close()
        }
    } catch {
        $out.error = $_.Exception.GetBaseException().Message
    }
    return $out
}

# A REG_SZ value, or $null.
function Read-String($Hklm, [string]$Key, [string]$Name) {
    try {
        $sub = $Hklm.OpenSubKey($Key, $false)
        if ($null -eq $sub) { return $null }
        try {
            $v = $sub.GetValue($Name, $null)
            if ($null -eq $v -or [string]$v -eq '') { return $null }
            return [string]$v
        } finally {
            $sub.Close()
        }
    } catch {
        return $null
    }
}

# The thumbprints in a CA's CACertHash (REG_MULTI_SZ, or REG_SZ on old
# CAs): hex digits only, upper case.
function Read-CertHashes($Hklm, [string]$Key) {
    $out = @()
    try {
        $sub = $Hklm.OpenSubKey($Key, $false)
        if ($null -eq $sub) { return , $out }
        try {
            $data = $sub.GetValue('CACertHash', $null)
            foreach ($h in @($data)) {
                if ($null -eq $h) { continue }
                $hex = ([string]$h -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
                if ($hex.Length -eq 40 -or $hex.Length -eq 64) { $out += $hex }
            }
        } finally {
            $sub.Close()
        }
    } catch { }
    return , $out
}

# The active certification authority on this host, if any: its name and
# values.
function Read-Cas($Hklm) {
    $cas = @()
    $active = Read-String $Hklm $CertSvc 'Active'
    if ($null -eq $active) { return , $cas }
    $caKey = "$CertSvc\$active"
    $cas += , ([ordered]@{
        name        = $active
        cert_hashes = (Read-CertHashes $Hklm $caKey)
        values      = @(
            (Read-Value $Hklm "$caKey\$PolicyModule" 'EditFlags'),
            (Read-Value $Hklm $caKey 'InterfaceFlags'),
            (Read-Value $Hklm $caKey 'RoleSeparationEnabled')
        )
    })
    return , $cas
}

# Management agents (schema v2): where each is read.
$CcmKey = 'SOFTWARE\Microsoft\CCM'
$SmsClientKey = 'SOFTWARE\Microsoft\SMS\Mobile Client'
$ScomKey = 'SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Agent Management Groups'
$WuKey = 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$HyperVGuestKey = 'SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'
$VmwareToolsKey = 'SOFTWARE\VMware, Inc.\VMware Tools'
$ServicesKey = 'SYSTEM\CurrentControlSet\Services'
# Backup agent services, by service name. The list is checked in a lab;
# a product missing here is simply not reported.
$BackupServices = @(
    @{ Product = 'Veeam'; Pattern = '^Veeam' },
    @{ Product = 'Commvault'; Pattern = '^(GxCVD|GxClMgrS|GxFWD)\(' },
    @{ Product = 'NetBackup'; Pattern = '^(bpinetd|nbdisco|NetBackup)' },
    @{ Product = 'DPM'; Pattern = '^DPMRA$' }
)

# Whether a key exists (it is opened read-only and closed).
function Test-Key($Hklm, [string]$Key) {
    $sub = $Hklm.OpenSubKey($Key, $false)
    if ($null -eq $sub) { return $false }
    $sub.Close()
    return $true
}

# A text value of an open key, or $null.
function Get-Text($Sub, [string]$Name) {
    $v = $Sub.GetValue($Name, $null)
    if ($null -eq $v -or [string]$v -eq '') { return $null }
    return ([string]$v).Trim()
}

# A DWORD of an open key, unsigned, or $null.
function Get-Number($Sub, [string]$Name) {
    $v = $Sub.GetValue($Name, $null)
    if ($null -eq $v) { return $null }
    if ($Sub.GetValueKind($Name) -ne [Microsoft.Win32.RegistryValueKind]::DWord) { return $null }
    return [int64][BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$v), 0)
}

# Runs $Read for one agent; a failure is recorded as its error, so the
# file says what was not read instead of "not there".
function Read-Part([scriptblock]$Read) {
    try {
        return (& $Read)
    } catch {
        return [ordered]@{ present = $false; error = $_.Exception.GetBaseException().Message }
    }
}

# The management agents on this host: presence, and the names of the
# servers they report to. No secrets: no credentials, no account names.
function Read-Agents($Hklm) {
    $sccm = Read-Part {
        $out = [ordered]@{ present = (Test-Key $Hklm $CcmKey); site_code = $null; error = $null }
        $sub = $Hklm.OpenSubKey($SmsClientKey, $false)
        if ($null -ne $sub) {
            try { $out.site_code = Get-Text $sub 'AssignedSiteCode' } finally { $sub.Close() }
        }
        $out
    }
    $scom = Read-Part {
        $out = [ordered]@{ present = $false; management_groups = @(); error = $null }
        $root = $Hklm.OpenSubKey($ScomKey, $false)
        if ($null -ne $root) {
            $out.present = $true
            try {
                foreach ($mg in $root.GetSubKeyNames()) {
                    $servers = @()
                    $parents = $root.OpenSubKey("$mg\Parent Health Services", $false)
                    if ($null -ne $parents) {
                        try {
                            foreach ($n in $parents.GetSubKeyNames()) {
                                $p = $parents.OpenSubKey($n, $false)
                                if ($null -eq $p) { continue }
                                try {
                                    $name = Get-Text $p 'NetworkName'
                                    if ($null -ne $name) { $servers += $name }
                                } finally { $p.Close() }
                            }
                        } finally { $parents.Close() }
                    }
                    $out.management_groups += , ([ordered]@{ name = $mg; servers = [string[]]$servers })
                }
            } finally { $root.Close() }
        }
        $out
    }
    $wsus = Read-Part {
        $out = [ordered]@{ present = $false; server = $null; status_server = $null; use_wu_server = $null; error = $null }
        $sub = $Hklm.OpenSubKey($WuKey, $false)
        if ($null -ne $sub) {
            $out.present = $true
            try {
                $out.server = Get-Text $sub 'WUServer'
                $out.status_server = Get-Text $sub 'WUStatusServer'
            } finally { $sub.Close() }
            $au = $Hklm.OpenSubKey("$WuKey\AU", $false)
            if ($null -ne $au) {
                try { $out.use_wu_server = Get-Number $au 'UseWUServer' } finally { $au.Close() }
            }
        }
        $out
    }
    $hyperv = Read-Part {
        $out = [ordered]@{ present = $false; host = $null; error = $null }
        $sub = $Hklm.OpenSubKey($HyperVGuestKey, $false)
        if ($null -ne $sub) {
            $out.present = $true
            try { $out.host = Get-Text $sub 'PhysicalHostNameFullyQualified' } finally { $sub.Close() }
        }
        $out
    }
    $vmware = Read-Part { [ordered]@{ present = (Test-Key $Hklm $VmwareToolsKey); error = $null } }
    $sshd = Read-Part {
        $out = [ordered]@{ present = $false; start = $null; error = $null }
        $sub = $Hklm.OpenSubKey("$ServicesKey\sshd", $false)
        if ($null -ne $sub) {
            $out.present = $true
            try { $out.start = Get-Number $sub 'Start' } finally { $sub.Close() }
        }
        $out
    }
    $backup = Read-Part {
        $out = [ordered]@{ present = $false; agents = @(); error = $null }
        $svc = $Hklm.OpenSubKey($ServicesKey, $false)
        if ($null -ne $svc) {
            try {
                foreach ($name in $svc.GetSubKeyNames()) {
                    foreach ($b in $BackupServices) {
                        if ($name -notmatch $b.Pattern) { continue }
                        $start = $null
                        $s = $svc.OpenSubKey($name, $false)
                        if ($null -ne $s) {
                            try { $start = Get-Number $s 'Start' } finally { $s.Close() }
                        }
                        $out.agents += , ([ordered]@{ product = $b.Product; service = $name; start = $start })
                        break
                    }
                }
            } finally { $svc.Close() }
        }
        $out.present = $out.agents.Count -gt 0
        $out
    }
    return [ordered]@{
        sccm   = $sccm
        scom   = $scom
        wsus   = $wsus
        hyperv = $hyperv
        vmware = $vmware
        sshd   = $sshd
        backup = $backup
    }
}

# What the agents part says, for the screen.
function Show-Agents($a) {
    $line = {
        param($label, $part, [string]$found)
        $shown = if ($null -ne $part.error) { "not read: $($part.error)" }
            elseif (-not $part.present) { 'not found' }
            else { $found }
        Write-Host ('  {0,-38} {1}' -f $label, $shown)
    }
    & $line 'SCCM client' $a.sccm $(if ($a.sccm.site_code) { "site $($a.sccm.site_code)" } else { 'found, site not set' })
    $scomServers = @($a.scom.management_groups | ForEach-Object { $_.servers } | Where-Object { $_ })
    & $line 'SCOM agent' $a.scom $(if ($scomServers.Count) { "reports to $($scomServers -join ', ')" } else { 'found, no management server set' })
    $wu = if ($a.wsus.server -and $a.wsus.use_wu_server -eq 1) { "uses $($a.wsus.server)" } else { 'policy set, no WSUS server in use' }
    & $line 'WSUS (Windows Update policy)' $a.wsus $wu
    & $line 'Hyper-V guest' $a.hyperv $(if ($a.hyperv.host) { "host $($a.hyperv.host)" } else { 'found, host not named' })
    & $line 'VMware Tools' $a.vmware 'found'
    & $line 'OpenSSH server (sshd)' $a.sshd $(if ($a.sshd.start -eq 4) { 'found, disabled' } else { 'found' })
    $agents = $a.backup.agents | ForEach-Object {
        $off = if ($_.start -eq 4) { ', disabled' } else { '' }
        "$($_.product) ($($_.service)$off)"
    }
    & $line 'Backup agents' $a.backup (@($agents) -join ', ')
}

# "17763.5458": build and update revision.
function Read-OsBuild($Hklm) {
    $key = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = Read-String $Hklm $key 'CurrentBuildNumber'
    if ($null -eq $build) { return $null }
    $ubr = Read-Value $Hklm $key 'UBR'
    if ($ubr.present -and $null -ne $ubr.value) {
        return "$build.$($ubr.value)"
    }
    return $build
}

function Show-Value($v) {
    $shown = if ($null -ne $v.error) {
        "not read: $($v.error)"
    } elseif (-not $v.present) {
        'not set'
    } else {
        '{0} (0x{0:X})' -f $v.value
    }
    Write-Host ('  {0,-38} {1}' -f $v.name, $shown)
}

# The file for one server. $IsDc: read the domain controller values. Any
# certification authority on it is read either way, and the management
# agents always. $IsCaHost: the directory lists it as a CA host, so its
# agents are written even when its registry names no active CA. Returns
# whether it had anything to write.
function Write-Settings($Hklm, [string]$Domain, [string]$HostName, [string]$DnsName, $Sid, $Dn, [bool]$IsDc, [bool]$IsCaHost) {
    $values = @()
    if ($IsDc) {
        foreach ($w in $Wanted) {
            $values += , (Read-Value $Hklm $w.Key $w.Name)
        }
    }
    $cas = Read-Cas $Hklm
    if (-not $IsDc -and -not $IsCaHost -and $cas.Count -eq 0) {
        return $false
    }
    $agents = Read-Agents $Hklm
    $doc = [ordered]@{
        schema  = $Schema
        tool    = 'Get-PathwardenTierZeroSettings.ps1'
        domain  = $Domain.ToLowerInvariant()
        dc      = [ordered]@{
            hostname           = $HostName.ToUpperInvariant()
            dns_name           = $DnsName.ToLowerInvariant()
            object_sid         = $Sid
            distinguished_name = $Dn
            os_build           = (Read-OsBuild $Hklm)
        }
        read_at = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
        values  = $values
        agents  = $agents
    }
    if ($cas.Count -gt 0) {
        $doc.cas = $cas
    }
    # Host and domain: servers of the same name in two domains get two files.
    $safeHost = $HostName.ToUpperInvariant() -replace '[^A-Z0-9_-]', '_'
    $safeDomain = $Domain.ToLowerInvariant() -replace '[^a-z0-9_.-]', '_'
    $path = Join-Path $OutputDirectory "pathwarden-tierzero-$safeHost.$safeDomain.json"
    $json = $doc | ConvertTo-Json -Depth 8
    # UTF-8 without a byte order mark.
    [IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))

    Write-Host ''
    Write-Host "$($DnsName.ToLowerInvariant()) (OS build $($doc.dc.os_build), read $($doc.read_at))"
    foreach ($v in $values) {
        Show-Value $v
    }
    foreach ($ca in $cas) {
        Write-Host "  Certification authority $($ca.name) ($($ca.cert_hashes.Count) certificate hash(es))"
        foreach ($v in $ca.values) {
            Show-Value $v
        }
    }
    Write-Host '  Management agents'
    Show-Agents $agents
    Write-Host "  Wrote $path"
    return $true
}

# The DNS names of the forest's certification authorities, from
# CN=Enrollment Services in the configuration partition.
function Get-CaHosts {
    $root = [ADSI]'LDAP://RootDSE'
    $config = [string]$root.configurationNamingContext
    $search = New-Object System.DirectoryServices.DirectorySearcher(
        [ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$config")
    $search.Filter = '(objectClass=pKIEnrollmentService)'
    [void]$search.PropertiesToLoad.Add('dNSHostName')
    $hosts = @()
    foreach ($r in $search.FindAll()) {
        $h = $r.Properties['dnshostname']
        if ($null -ne $h -and $h.Count -gt 0) { $hosts += [string]$h[0] }
    }
    return , $hosts
}

if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    throw "The output folder $OutputDirectory does not exist."
}
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).ProviderPath

if (-not $AllDomainControllers -and -not $AllCertificationAuthorities) {
    # Get-CimInstance: Get-WmiObject is gone from PowerShell 7.
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    if (-not $cs.PartOfDomain) {
        throw 'This computer is not joined to a domain.'
    }
    # The 64-bit registry view, even from a 32-bit PowerShell.
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        # 4: backup domain controller, 5: primary domain controller.
        $isDc = $cs.DomainRole -ge 4
        $isCa = $null -ne (Read-String $hklm $CertSvc 'Active')
        if (-not $isDc -and -not $isCa) {
            Write-Warning 'This computer is neither a domain controller nor a certification authority. Pathwarden uses these values only for those.'
            # Read as before: the values say what they say.
            $isDc = $true
        }
        $hostName = $env:COMPUTERNAME
        $dnsName = "$($cs.DNSHostName).$($cs.Domain)"
        # The computer account, resolved by the local security authority.
        $sid = $null
        try {
            $sid = (New-Object System.Security.Principal.NTAccount("$hostName`$")).Translate(
                [System.Security.Principal.SecurityIdentifier]).Value
        } catch { }
        # The computer's distinguished name as Group Policy last recorded it.
        $dn = Read-String $hklm 'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine' 'Distinguished-Name'
        [void](Write-Settings $hklm $cs.Domain $hostName $dnsName $sid $dn $isDc $isCa)
    } finally {
        $hklm.Close()
    }
} else {
    # Each host once: (DNS name, domain, read the DC values).
    $targets = [ordered]@{}
    if ($AllDomainControllers) {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        foreach ($dc in $domain.DomainControllers) {
            $targets[([string]$dc.Name).ToLowerInvariant()] = @{ Domain = $domain.Name; IsDc = $true; IsCaHost = $false }
        }
    }
    if ($AllCertificationAuthorities) {
        foreach ($h in (Get-CaHosts)) {
            $key = $h.ToLowerInvariant()
            if ($targets.Contains($key)) {
                $targets[$key].IsCaHost = $true
            } else {
                $dot = $key.IndexOf('.')
                $dom = if ($dot -gt 0) { $key.Substring($dot + 1) } else { '' }
                $targets[$key] = @{ Domain = $dom; IsDc = $false; IsCaHost = $true }
            }
        }
    }
    $failed = 0
    foreach ($dnsName in $targets.Keys) {
        $t = $targets[$dnsName]
        $hostName = $dnsName.Split('.')[0]
        try {
            $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine, $dnsName)
        } catch {
            Write-Warning "$($dnsName): could not open the registry: $($_.Exception.Message)"
            $failed++
            continue
        }
        try {
            [void](Write-Settings $hklm $t.Domain $hostName $dnsName $null $null $t.IsDc $t.IsCaHost)
        } finally {
            $hklm.Close()
        }
    }
    if ($failed -gt 0) {
        Write-Warning "$failed server(s) not read. Run the script on each of them instead."
    }
}
Write-Host ''
Write-Host 'Nothing was changed. Put the file(s) beside the collection you load into Pathwarden, or in a Tier Zero settings folder.'
