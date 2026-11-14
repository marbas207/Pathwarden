<#
.SYNOPSIS
Builds a zip of Pathwarden numbers that is safe to share: counts, rule IDs
and hashed IDs, no object, account or domain names.

.DESCRIPTION
VERSIONS WITH `pathwarden diagnose`
===================================

Use the built-in command instead: it makes the bundle from a saved run
(timings, completeness, error counts, collection settings, posture and the
plan's size), with every name replaced and the same name search:

    pathwarden diagnose --bundle

or Download diagnostics under Collection performance on the run's page.
See docs/collect.md, "Measuring a slow collection". This script stays for
older versions, and for a collection log or zip you still have.

HOW TO USE IT
=============

 1. Copy this file and diagnostics-bundle.cmd into the folder where
    pathwarden.exe is.
 2. In Pathwarden, switch to the environment you want numbers for (the
    environment picker at the top of the app). The bundle is made from the
    current one.
 3. Double-click diagnostics-bundle.cmd.
    Still have the collection zip (SharpHound, or `pathwarden collect`)?
    Drag it onto diagnostics-bundle.cmd instead: the bundle then also
    scores it with this Pathwarden.
 4. Read the last lines in the window:
    - "Written ...zip": the zip is on your Desktop. Open it and look
      through it, then send it.
    - "Not written: these files contain names": nothing was written. The
      window lists the file and the name it found; leave that file out or
      ask for help (send the file name, not the name it found).
    - "No environment ...": the window lists the environments; run it from
      PowerShell with -Environment "<name>" (below).

From PowerShell, with options (all optional):

    powershell -ExecutionPolicy Bypass -File .\diagnostics-bundle.ps1 `
        -Environment "Contoso prod" -Collection D:\collect\contoso.zip `
        -Log D:\collect\collect.log -ExtraNames "Contoso","Chicago"

WHAT IS IN THE ZIP
==================

Copies from one environment of a Pathwarden workspace:

  - pathwarden-state\history\*.json  one point per run (exposure, score,
                                     findings by severity, changes,
                                     collection completeness in percent,
                                     each zone's counts and status, the
                                     remediation plan's length)
  - pathwarden-state\findings.json   findings by rule, severity, status and
                                     dates, identified by fingerprint hashes

and adds, when given:

  - posture.json   `pathwarden posture --json` on a collection you already
                   have (-Collection), with the environment's settings and
                   the domain names blanked
  - timing.txt     the `Timing:` and `[timing]` lines from a collection log
                   (-Log)
  - system.txt     Pathwarden version, Windows version, CPU cores, memory

Then it searches every file for the names Pathwarden knows from that
environment's analyzed runs (domains, their labels, domain SIDs, account,
group and computer names) and refuses to write the zip if any is found.

Never copied: collections, run folders (objects, graph, report.html,
summary.json, which names the next step's objects), uploads, settings.

.EXAMPLE
.\diagnostics-bundle.ps1 -Environment "Contoso prod" -Collection D:\collect\contoso.zip -Log D:\collect\collect.log
#>
[CmdletBinding()]
param(
    # Environment name or ID (default: the current one).
    [string]$Environment,
    # The workspace (default: the one `pathwarden ui` uses).
    [string]$Workspace = (Join-Path $env:LOCALAPPDATA 'Pathwarden'),
    # A collection to score with this Pathwarden: zip, folder or .json files.
    [string[]]$Collection,
    # A collection log (`pathwarden collect -v 2> collect.log`, or the job log
    # copied from the UI) to take the timing lines from.
    [string]$Log,
    # pathwarden.exe (default: the one next to this script, else the one on
    # PATH).
    [string]$Pathwarden,
    # Where to write the zip (default: the Desktop).
    [string]$Out,
    # More names to search for (a company name, a site, a person).
    [string[]]$ExtraNames = @()
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

if (-not $Pathwarden) {
    $Pathwarden = Join-Path $PSScriptRoot 'pathwarden.exe'
    if (-not (Test-Path $Pathwarden)) { $Pathwarden = 'pathwarden' }
}

function Write-Utf8([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding $false))
}

# --- The environment -------------------------------------------------------

$registry = Join-Path $Workspace 'environments.json'
$envId = 'default'
$envName = 'Default'
$envDomains = @()
if (Test-Path $registry) {
    $reg = Get-Content -Raw -Encoding UTF8 $registry | ConvertFrom-Json
    $want = $Environment
    if (-not $want) { $want = $reg.current }
    $match = @($reg.environments | Where-Object { $_.id -eq $want -or $_.name -eq $want })
    if ($match.Count -ne 1) {
        $known = ($reg.environments | ForEach-Object { $_.name }) -join ', '
        throw "No environment '$want' in $Workspace. Known: $known"
    }
    $envId = $match[0].id
    $envName = $match[0].name
    if ($match[0].PSObject.Properties['domains']) { $envDomains = @($match[0].domains) }
} elseif ($Environment -and $Environment -ne 'default') {
    throw "$Workspace has no environments.json, so only the Default environment exists."
}
if ($envId -eq 'default') { $envDir = $Workspace } else { $envDir = Join-Path (Join-Path $Workspace 'environments') $envId }
$state = Join-Path $envDir 'pathwarden-state'
Write-Host "Environment: $envName ($envDir)"

# --- Names to search for ---------------------------------------------------

# Upper-cased single words, phrases with spaces, and SID prefixes.
$words = New-Object 'System.Collections.Generic.HashSet[string]'
$phrases = New-Object 'System.Collections.Generic.HashSet[string]'
$sids = New-Object 'System.Collections.Generic.HashSet[string]'
# Domain labels too common to mean anything.
$generic = @('LOCAL', 'COM', 'NET', 'ORG', 'INT', 'LAN', 'CORP', 'AD', 'DOMAIN', 'INTERNAL', 'HOME')
# Objects every domain has (default containers, groups, accounts and
# certificate templates): finding one of these words identifies nothing.
$builtin = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($w in @('USERS', 'USER', 'COMPUTERS', 'COMPUTER', 'MACHINE', 'MICROSOFT', 'SYSTEM', 'BUILTIN',
        'ADMINISTRATOR', 'ADMINISTRATORS', 'GUEST', 'GUESTS', 'KRBTGT', 'DOMAIN ADMINS', 'DOMAIN USERS',
        'DOMAIN COMPUTERS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS', 'PROGRAM DATA', 'POLICIES', 'CONFIGURATION',
        'SCHEMA', 'SERVICES', 'PUBLIC KEY SERVICES', 'ENROLLMENT SERVICES', 'CERTIFICATE TEMPLATES',
        'DOMAIN CONTROLLERS', 'TIER ZERO', 'EVERYONE', 'AUTHENTICATED USERS')) { [void]$builtin.Add($w) }

function Add-Name([string]$Name) {
    $n = $Name.Trim().ToUpperInvariant()
    if ($n.Length -lt 4 -or $builtin.Contains($n)) { return }
    if ($n.Contains(' ')) { [void]$phrases.Add($n) } else { [void]$words.Add($n) }
}
function Add-Domain([string]$Domain) {
    $d = $Domain.Trim().ToUpperInvariant()
    if (-not $d) { return }
    [void]$words.Add($d)
    foreach ($label in $d.Split('.')) {
        if ($label.Length -ge 3 -and $generic -notcontains $label) { [void]$words.Add($label) }
    }
}

foreach ($d in $envDomains) { Add-Domain $d }
foreach ($n in $ExtraNames) { Add-Name $n; Add-Domain $n }

# The environment's runs: a run's summary names its environment (absent for
# Default).
$runs = @()
$runsDir = Join-Path $Workspace 'runs'
if (Test-Path $runsDir) {
    foreach ($dir in Get-ChildItem -Directory $runsDir) {
        $summary = Join-Path $dir.FullName 'summary.json'
        if (-not (Test-Path $summary)) { continue }
        $s = Get-Content -Raw -Encoding UTF8 $summary | ConvertFrom-Json
        $runEnv = 'default'
        if ($s.PSObject.Properties['environment'] -and $s.environment) { $runEnv = $s.environment }
        if ($runEnv -ne $envId) { continue }
        $runs += $dir.FullName
        foreach ($key in 'domains', 'trusted_domains') {
            if ($s.PSObject.Properties[$key]) { foreach ($d in @($s.$key)) { Add-Domain $d } }
        }
    }
}

# objects.json.gz can be hundreds of MB: read it in chunks (overlapping, so a
# name across a boundary is still seen) and pull out each object's name (the
# second field of its record: "NAME@DOMAIN", or a computer's host name) and
# the SIDs.
$nameRe = New-Object regex '\[\s*"[^"\\]{1,200}"\s*,\s*"([^"\\]{1,512})"'
$sidRe = New-Object regex 'S-1-5-21-\d+-\d+-\d+'
foreach ($run in $runs) {
    $objects = Join-Path $run 'objects.json.gz'
    if (-not (Test-Path $objects)) { continue }
    Write-Host "Reading names from $(Split-Path -Leaf $run)"
    $file = [IO.File]::OpenRead($objects)
    try {
        $gz = New-Object IO.Compression.GZipStream($file, [IO.Compression.CompressionMode]::Decompress)
        $reader = New-Object IO.StreamReader($gz, [Text.Encoding]::UTF8)
        $buf = New-Object char[] (4MB)
        $carry = ''
        while (($read = $reader.Read($buf, 0, $buf.Length)) -gt 0) {
            $text = $carry + [string]::new($buf, 0, $read)
            foreach ($m in $nameRe.Matches($text)) {
                $name = $m.Groups[1].Value
                $at = $name.LastIndexOf('@')
                if ($at -gt 0) {
                    Add-Name $name.Substring(0, $at)
                    Add-Domain $name.Substring($at + 1)
                } else {
                    # A host name: the whole of it and its short name.
                    Add-Name $name
                    Add-Name $name.Split('.')[0]
                }
            }
            foreach ($m in $sidRe.Matches($text)) { [void]$sids.Add($m.Value) }
            $keep = [Math]::Min(600, $text.Length)
            $carry = $text.Substring($text.Length - $keep)
        }
    } finally {
        $file.Dispose()
    }
}
Write-Host ("Names to search for: {0} words, {1} phrases, {2} domain SIDs, from {3} run(s)" -f $words.Count, $phrases.Count, $sids.Count, $runs.Count)
if ($runs.Count -eq 0 -and $envDomains.Count -eq 0 -and $ExtraNames.Count -eq 0) {
    Write-Warning "No analyzed runs or domains for this environment, so there are no names to search for. Pass -ExtraNames to search for some."
}

# --- The bundle --------------------------------------------------------------

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$stage = Join-Path $env:TEMP "pathwarden-diagnostics-$stamp"
New-Item -ItemType Directory -Path $stage | Out-Null
$files = @()

$history = Join-Path $state 'history'
if (Test-Path $history) {
    New-Item -ItemType Directory -Path (Join-Path $stage 'history') | Out-Null
    foreach ($h in Get-ChildItem -File -Filter *.json $history) {
        Copy-Item $h.FullName (Join-Path $stage 'history')
        $files += "history\$($h.Name)"
    }
}
$findings = Join-Path $state 'findings.json'
if (Test-Path $findings) {
    Copy-Item $findings $stage
    $files += 'findings.json'
}

# Strings Pathwarden writes itself (statuses, reasons, the grade); every
# other string in posture JSON is a domain, host or CA name.
$ownStrings = @('status', 'reason', 'exposure_grade', 'zone')
$placeholders = @{}
# Replaces each name with a placeholder named after its field (`domain-1`,
# `dc-1`), the same one wherever the same name appears.
function Protect-Strings($Value, [string]$Key) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        if ($ownStrings -contains $Key) { return $Value }
        $u = $Value.ToUpperInvariant()
        if (-not $placeholders.ContainsKey($u)) {
            $kind = $Key
            if (-not $kind) { $kind = 'name' }
            $n = @($placeholders.Values | Where-Object { $_ -like "$kind-*" }).Count + 1
            $placeholders[$u] = "$kind-$n"
        }
        return $placeholders[$u]
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        foreach ($prop in $Value.PSObject.Properties) { $prop.Value = Protect-Strings $prop.Value $prop.Name }
        return $Value
    }
    if ($Value -is [System.Array]) {
        return ,@($Value | ForEach-Object { Protect-Strings $_ $Key })
    }
    return $Value
}

$version = ''
try { $version = (& $Pathwarden --version 2>$null | Out-String).Trim() } catch { }

if ($Collection) {
    if (-not $version) { throw "Can't run '$Pathwarden'. Pass -Pathwarden with the path to pathwarden.exe." }
    $pwArgs = @('posture', '--json')
    foreach ($c in $Collection) { $pwArgs += @('-i', $c) }
    # The environment's settings (Tier Zero additions, stale days), without
    # --env so nothing is written to its history.
    $config = Join-Path $envDir 'pathwarden.toml'
    if (Test-Path $config) { $pwArgs += @('-c', $config) }
    Write-Host "Scoring the collection with $version"
    $json = (& $Pathwarden @pwArgs | Out-String)
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) { throw "pathwarden posture failed (exit $LASTEXITCODE)" }
    $posture = Protect-Strings ($json | ConvertFrom-Json) ''
    Write-Utf8 (Join-Path $stage 'posture.json') ($posture | ConvertTo-Json -Depth 20)
    $files += 'posture.json'
}

if ($Log) {
    $lines = @(Get-Content -Encoding UTF8 $Log | Where-Object { $_ -match '(^|\s)Timing: |\[timing\]' })
    if ($lines.Count -eq 0) { Write-Warning "No Timing: or [timing] lines in $Log." }
    Write-Utf8 (Join-Path $stage 'timing.txt') (($lines -join "`r`n") + "`r`n")
    $files += 'timing.txt'
}

if (-not $version) {
    $version = 'not found (copy this script next to pathwarden.exe, or pass -Pathwarden)'
    Write-Warning "pathwarden.exe not found next to this script or on PATH: the bundle has no version and nothing was scored."
}
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$system = @(
    "Pathwarden: $version",
    "Windows: $($os.Caption) $($os.Version)",
    "Logical processors: $($cs.NumberOfLogicalProcessors)",
    ("Memory: {0:N1} GB" -f ($cs.TotalPhysicalMemory / 1GB)),
    "Environment runs analyzed: $($runs.Count)"
) -join "`r`n"
Write-Utf8 (Join-Path $stage 'system.txt') ($system + "`r`n")
$files += 'system.txt'

# --- The search ----------------------------------------------------------------

$hits = @()
foreach ($f in Get-ChildItem -Recurse -File $stage) {
    $text = [IO.File]::ReadAllText($f.FullName).ToUpperInvariant()
    $rel = $f.FullName.Substring($stage.Length + 1)
    foreach ($token in [regex]::Split($text, '[^A-Z0-9_.$-]+')) {
        $t = $token.Trim('.')
        if (-not $t) { continue }
        # The token, and each part of a dotted one (a host name whose domain
        # labels were dropped from the list as generic).
        foreach ($part in @($t) + $t.Split('.')) {
            if ($part -and -not $builtin.Contains($part) -and $words.Contains($part)) { $hits += "${rel}: $t"; break }
        }
    }
    foreach ($p in $phrases) { if ($text.Contains($p)) { $hits += "${rel}: $p" } }
    foreach ($s in $sids) { if ($text.Contains($s)) { $hits += "${rel}: $s" } }
}
if ($hits.Count -gt 0) {
    Write-Host ''
    Write-Host 'Not written: these files contain names from the environment.' -ForegroundColor Red
    $hits | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }
    Write-Host "Review or edit them in $stage, or leave the file out."
    exit 2
}

if (-not $Out) { $Out = Join-Path ([Environment]::GetFolderPath('Desktop')) "pathwarden-diagnostics-$stamp.zip" }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $Out
Write-Host ''
Write-Host "Written $Out" -ForegroundColor Green
Write-Host "No environment names found in:"
$files | ForEach-Object { Write-Host "  $_" }
Write-Host "Look through $stage before you send it."
exit 0
