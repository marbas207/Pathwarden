# Builds both Pathwarden variants and packages each as a zip in dist\:
#   pathwarden-<version>-windows-x64-full.zip  (built-in collector, and the
#                                              desktop window: `desktop`)
#   pathwarden-<version>-windows-x64-lean.zip  (no built-in collector)
# Each holds pathwarden.exe, the ServiceNow and Jira plugins, the license, the
# notices, THIRD-PARTY-LICENSES.md (every crate's license text, from
# cargo-about), CycloneDX SBOMs of the three executables (sbom\), the README
# and the example configuration. Next to each zip goes its SBOM
# (<zip name>.cdx.json), and dist\SHA256SUMS.txt is written fresh with the
# hashes of exactly this run's files.
#
# Builds use Cargo.lock as committed (--locked) and the toolchain that
# rust-toolchain.toml pins. The script refuses to package a working tree with
# uncommitted changes, so an archive always matches a commit; -Force packages
# anyway (for a local test build). -OutDir writes somewhere other than dist\.
#
# Needs cargo-about and cargo-cyclonedx:
#   cargo install cargo-about --locked --features cli
#   cargo install cargo-cyclonedx --locked
#
# Code signing (optional): set PW_SIGN_ENDPOINT, PW_SIGN_ACCOUNT,
# PW_SIGN_PROFILE and PW_SIGN_DLIB to sign the executables with Azure Artifact
# Signing before they are zipped; see docs/dev/building.md, "Code signing".
# Without them the executables are unsigned.
#
#   powershell -NoProfile -File scripts\package.ps1 [-Force] [-OutDir <folder>]
param([switch]$Force, [string]$OutDir)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Uncommitted changes (ignored files such as target\ and dist\ don't count).
# git's stderr must not stop the script (Windows PowerShell turns it into an
# error under 'Stop'), and git may be missing altogether.
$ErrorActionPreference = 'Continue'
try {
    $dirty = & git status --porcelain 2>$null
    $isCheckout = ($LASTEXITCODE -eq 0)
    $commitTime = & git log -1 --format=%ct 2>$null
} catch {
    $isCheckout = $false
}
$ErrorActionPreference = 'Stop'
if (-not $isCheckout) {
    if (-not $Force) { throw 'Not a git checkout, so the source state is unknown; run with -Force to package anyway.' }
    Write-Warning 'Not a git checkout; packaging anyway (-Force).'
} elseif ($dirty) {
    if (-not $Force) { throw "The working tree has uncommitted changes:`n$($dirty -join "`n")`nCommit or stash them, or run with -Force for a test build." }
    Write-Warning 'The working tree has uncommitted changes; packaging anyway (-Force).'
}

# Runs a command whose stderr is progress, not failure (see the git check).
function Invoke-Native([string]$Exe, [string[]]$ArgList) {
    $ErrorActionPreference = 'Continue'
    try { & $Exe @ArgList } finally { $ErrorActionPreference = 'Stop' }
    if ($LASTEXITCODE -ne 0) { throw "$Exe $($ArgList -join ' ') failed (exit $LASTEXITCODE)" }
}
function Invoke-Cargo([string[]]$CargoArgs) { Invoke-Native 'cargo' $CargoArgs }

# The tools for the notices and the SBOMs, checked before the long build.
foreach ($tool in @(
        @{ Sub = 'about'; Install = 'cargo install cargo-about --locked --features cli' },
        @{ Sub = 'cyclonedx'; Install = 'cargo install cargo-cyclonedx --locked' })) {
    $ErrorActionPreference = 'Continue'
    & cargo $tool.Sub --version *> $null
    $ok = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = 'Stop'
    if (-not $ok) { throw "cargo $($tool.Sub) is missing; install it with: $($tool.Install)" }
}

# --- Code signing (optional; see docs/dev/building.md, "Code signing") ---------
# Azure Artifact Signing through signtool and Microsoft's dlib. All four
# variables, or none.
$signVars = 'PW_SIGN_ENDPOINT', 'PW_SIGN_ACCOUNT', 'PW_SIGN_PROFILE', 'PW_SIGN_DLIB'
$signSet = @($signVars | Where-Object { [Environment]::GetEnvironmentVariable($_) })
$sign = $null
if ($signSet.Count -eq 0) {
    Write-Host 'Signing: PW_SIGN_* not set, so the executables will be unsigned.'
} elseif ($signSet.Count -lt $signVars.Count) {
    $missing = $signVars | Where-Object { $signSet -notcontains $_ }
    throw "Code signing needs all of $($signVars -join ', '); missing: $($missing -join ', ')"
} else {
    $signtool = $env:PW_SIGNTOOL
    if (-not $signtool) {
        # The newest x64 signtool of the Windows SDK (the dlib is x64 too).
        $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object { [version]($_.Directory.Parent.Name) } | Select-Object -Last 1 -ExpandProperty FullName
    }
    if (-not $signtool -or -not (Test-Path -LiteralPath $signtool)) { throw 'signtool.exe not found: install the Windows SDK signing tools or set PW_SIGNTOOL' }
    if (-not (Test-Path -LiteralPath $env:PW_SIGN_DLIB)) { throw "PW_SIGN_DLIB: $env:PW_SIGN_DLIB does not exist" }
    $sign = @{ Tool = $signtool; Metadata = Join-Path ([System.IO.Path]::GetTempPath()) "pathwarden-sign-$PID.json" }
    $meta = [ordered]@{ Endpoint = $env:PW_SIGN_ENDPOINT; CodeSigningAccountName = $env:PW_SIGN_ACCOUNT; CertificateProfileName = $env:PW_SIGN_PROFILE }
    [System.IO.File]::WriteAllText($sign.Metadata, ($meta | ConvertTo-Json), (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Signing: on, account $env:PW_SIGN_ACCOUNT, profile $env:PW_SIGN_PROFILE, with $signtool"
}

# Signs the executables in place (Authenticode, SHA-256, timestamped) and
# checks each signature.
function Invoke-Sign([string[]]$Files) {
    Invoke-Native $sign.Tool (@('sign', '/v', '/fd', 'SHA256', '/tr', 'http://timestamp.acs.microsoft.com', '/td', 'SHA256',
            '/dlib', $env:PW_SIGN_DLIB, '/dmdf', $sign.Metadata) + $Files)
    foreach ($f in $Files) {
        $s = Get-AuthenticodeSignature -LiteralPath $f
        if ($s.Status -ne 'Valid') { throw "signature of ${f}: $($s.Status) $($s.StatusMessage)" }
        Write-Host "  signed: $(Split-Path -Leaf $f) ($($s.SignerCertificate.Subject))"
    }
}

$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
$dist = if ($OutDir) { $OutDir } else { Join-Path $root 'dist' }
New-Item -ItemType Directory -Force $dist | Out-Null
$dist = (Resolve-Path -LiteralPath $dist).Path
$sumsFile = Join-Path $dist 'SHA256SUMS.txt'
if (Test-Path $sumsFile) { Remove-Item -Force $sumsFile }
# SBOM timestamps from the commit, so a rebuild gives the same SBOM.
if ($commitTime) { $env:SOURCE_DATE_EPOCH = "$commitTime".Trim() }

# Zips the files under $Folder (absolute paths), named relative to it.
# Not Compress-Archive: in Windows PowerShell 5.1 it writes names such as
# scripts\x.ps1, and the zip format wants scripts/x.ps1 (unzip on Linux
# warns, or makes a file with a backslash in its name).
function New-Zip([string]$Folder, [string]$Zip) {
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $base = $Folder.TrimEnd('\') + '\'
    $archive = [System.IO.Compression.ZipFile]::Open($Zip, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in Get-ChildItem -LiteralPath $Folder -Recurse -File -Force) {
            $name = $file.FullName.Substring($base.Length).Replace('\', '/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $name, [System.IO.Compression.CompressionLevel]::Optimal)
        }
    } finally {
        $archive.Dispose()
    }
}

# Reads the finished zip back: every entry name uses forward slashes, and
# the archive holds exactly the files that were staged.
function Test-Zip([string]$Zip, [string[]]$Expected) {
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Zip)
    try { $names = @($archive.Entries | ForEach-Object { $_.FullName }) } finally { $archive.Dispose() }
    $bad = @($names | Where-Object { $_.Contains('\') })
    if ($bad) { throw "$Zip has entry names with backslashes: $($bad -join ', ')" }
    $diff = Compare-Object ($Expected | Sort-Object) ($names | Sort-Object)
    if ($diff) { throw "$Zip entries differ from the staged files:`n$($diff | Out-String)" }
    Write-Host "  zip entries: $($names.Count), forward slashes only"
}

# Checks a staged pathwarden.exe before it is zipped: the version, and that
# `ui --help` lists --window in the full build (the desktop window) and not
# in the lean one; the packaging stops otherwise. Each variant also builds
# into a target folder of its own: on Windows a binary's file name carries
# no feature hash, so any other `cargo build --release` in the shared
# target\ (a plain build, without `desktop`) writes the same
# target\release\pathwarden.exe.
function Test-Staged([string]$Exe, [string]$Variant) {
    # Away from the user's own app data (the help touches none; to be sure).
    $saved = $env:LOCALAPPDATA
    $env:LOCALAPPDATA = Join-Path ([System.IO.Path]::GetTempPath()) "pathwarden-package-check-$PID"
    New-Item -ItemType Directory -Force $env:LOCALAPPDATA | Out-Null
    $ErrorActionPreference = 'Continue'
    try {
        $shown = (& $Exe --version 2>&1 | Out-String).Trim()
        $help = (& $Exe ui --help 2>&1 | Out-String)
    } finally {
        $ErrorActionPreference = 'Stop'
        Remove-Item -Recurse -Force $env:LOCALAPPDATA -ErrorAction SilentlyContinue
        $env:LOCALAPPDATA = $saved
    }
    if ($shown -ne "pathwarden $version") { throw "$Variant build: $Exe says '$shown', expected 'pathwarden $version'" }
    $window = $help -match '(?m)^\s+--window\b'
    if ($Variant -eq 'full' -and -not $window) { throw "full build: 'ui --help' of $Exe has no --window (built without the desktop feature)" }
    if ($Variant -eq 'lean' -and $window) { throw "lean build: 'ui --help' of $Exe lists --window (built with the desktop feature)" }
    Write-Host "  checked: $shown, --window $(if ($window) { 'present' } else { 'absent' })"
}

# THIRD-PARTY-LICENSES.md: the license texts of every crate built into each
# of the three executables, as this variant builds them for Windows
# (cargo-about, with about.toml and the template about.hbs). --fail stops on
# a crate whose license can't be identified.
function New-Licenses([string[]]$FeatureArgs, [string]$Out) {
    $text = "# Third-party licenses: Rust crates`n`n" +
        "The license texts of the Rust crates built into this release, per executable, generated from`n" +
        "Cargo.lock by cargo-about (https://github.com/EmbarkStudios/cargo-about). THIRD-PARTY-NOTICES.md`n" +
        "covers the rest: RustHound-CE, the BloodHound Query Library, Cytoscape.js, the modified ldap3`n" +
        "and smb2-client, and the WebView2 loader.`n"
    $part = Join-Path ([System.IO.Path]::GetTempPath()) "pathwarden-licenses-$PID.md"
    foreach ($exe in @(
            @{ Name = 'pathwarden'; Manifest = 'crates\pathwarden-cli\Cargo.toml'; Features = $FeatureArgs },
            @{ Name = 'pathwarden-output-servicenow'; Manifest = 'crates\pathwarden-output-servicenow\Cargo.toml'; Features = @() },
            @{ Name = 'pathwarden-output-jira'; Manifest = 'crates\pathwarden-output-jira\Cargo.toml'; Features = @() })) {
        Invoke-Cargo (@('about', 'generate', '--locked', '--fail', '-m', $exe.Manifest,
                '--target', 'x86_64-pc-windows-msvc', '-o', $part) + $exe.Features + @('about.hbs'))
        $text += "`n## $($exe.Name)`n`n" + [System.IO.File]::ReadAllText($part)
    }
    Remove-Item -LiteralPath $part -ErrorAction SilentlyContinue
    [System.IO.File]::WriteAllText($Out, $text, (New-Object System.Text.UTF8Encoding $false))
}

# CycloneDX SBOMs (JSON, spec 1.5) of pathwarden and both plugins, as built
# for this variant. cargo-cyclonedx writes one file next to each workspace
# crate's Cargo.toml; the three shipped ones are moved to $Folder and the
# rest removed. Local paths in the references are replaced, so the SBOM
# doesn't name the build machine's folders.
function New-Sboms([string[]]$FeatureArgs, [string]$Folder) {
    $tag = "pathwarden-package-sbom-$PID"
    try {
        Invoke-Cargo (@('cyclonedx', '-f', 'json', '--spec-version', '1.5', '--target', 'x86_64-pc-windows-msvc',
                '--override-filename', $tag, '-q') + $FeatureArgs)
        New-Item -ItemType Directory -Force $Folder | Out-Null
        $rootUrl = 'file:///' + $root.Replace('\', '/')
        $rootJson = $root.Replace('\', '\\')
        foreach ($crate in 'pathwarden-cli', 'pathwarden-output-servicenow', 'pathwarden-output-jira') {
            $text = [System.IO.File]::ReadAllText((Join-Path $root "crates\$crate\$tag.json"))
            $text = $text.Replace($rootUrl, 'file:///pathwarden').Replace($rootJson, 'pathwarden')
            $name = if ($crate -eq 'pathwarden-cli') { 'pathwarden' } else { $crate }
            [System.IO.File]::WriteAllText((Join-Path $Folder "$name.cdx.json"), $text, (New-Object System.Text.UTF8Encoding $false))
        }
    } finally {
        Get-ChildItem -Path (Join-Path $root "crates\*\$tag.json") -File -ErrorAction SilentlyContinue | Remove-Item -Force
    }
}

$variants = @(
    # The desktop window (`pathwarden ui` opens it on Windows desktops) adds about 0.7 MB.
    @{ Name = 'full'; Target = 'target\full'; Features = @('--features', 'desktop')
        Args = @('build', '--release', '--locked', '-p', 'pathwarden', '-p', 'pathwarden-output-servicenow', '-p', 'pathwarden-output-jira', '--features', 'pathwarden/desktop', '--target-dir', 'target\full') },
    @{ Name = 'lean'; Target = 'target\lean'; Features = @('--no-default-features')
        Args = @('build', '--release', '--locked', '-p', 'pathwarden', '--no-default-features', '--target-dir', 'target\lean') }
)

$sums = @()
try {
    foreach ($v in $variants) {
        Write-Host "Building $($v.Name)..."
        Invoke-Cargo $v.Args
        if ($v.Name -eq 'lean') {
            Invoke-Cargo @('build', '--release', '--locked', '-p', 'pathwarden-output-servicenow', '-p', 'pathwarden-output-jira', '--target-dir', 'target\lean')
        }
        $bin = Join-Path $root "$($v.Target)\release"
        $name = "pathwarden-$version-windows-x64-$($v.Name)"
        $stage = Join-Path $dist $name
        if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
        New-Item -ItemType Directory $stage | Out-Null
        $exes = 'pathwarden.exe', 'pathwarden-output-servicenow.exe', 'pathwarden-output-jira.exe'
        Copy-Item ($exes | ForEach-Object { Join-Path $bin $_ }) $stage
        Test-Staged (Join-Path $stage 'pathwarden.exe') $v.Name
        if ($sign) {
            Invoke-Sign ($exes | ForEach-Object { Join-Path $stage $_ })
            Test-Staged (Join-Path $stage 'pathwarden.exe') $v.Name
        }
        Copy-Item LICENSE, THIRD-PARTY-NOTICES.md, README.md, pathwarden.example.toml $stage
        Write-Host '  writing THIRD-PARTY-LICENSES.md and the SBOMs...'
        New-Licenses $v.Features (Join-Path $stage 'THIRD-PARTY-LICENSES.md')
        New-Sboms $v.Features (Join-Path $stage 'sbom')
        # Run on a domain admin's Windows machine, whatever the collector's OS.
        New-Item -ItemType Directory "$stage\scripts" | Out-Null
        Copy-Item scripts\collector\*.ps1 "$stage\scripts"
        $zip = "$stage.zip"
        if (Test-Path $zip) { Remove-Item -Force $zip }
        $staged = @(Get-ChildItem -LiteralPath $stage -Recurse -File -Force | ForEach-Object { $_.FullName.Substring($stage.Length + 1).Replace('\', '/') })
        New-Zip $stage $zip
        Test-Zip $zip $staged
        # The executable's SBOM beside the zip too, for the release page.
        $sbom = "$stage.cdx.json"
        Copy-Item (Join-Path $stage 'sbom\pathwarden.cdx.json') $sbom -Force
        Remove-Item -Recurse -Force $stage
        foreach ($f in $zip, $sbom) {
            $hash = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
            $sums += "$hash  $(Split-Path -Leaf $f)"
        }
        Write-Host ("  {0} ({1:N1} MB)" -f (Split-Path -Leaf $zip), ((Get-Item $zip).Length / 1MB))
    }
} finally {
    if ($sign) { Remove-Item -LiteralPath $sign.Metadata -ErrorAction SilentlyContinue }
}
# One fresh file, LF line endings and no BOM, so `sha256sum -c` reads it too.
[System.IO.File]::WriteAllText($sumsFile, (($sums -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding $false))
if (-not $sign) { Write-Host 'Unsigned: the executables are not code-signed (PW_SIGN_* not set).' }
Write-Host "Done: $dist"
