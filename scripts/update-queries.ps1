# Refreshes the pinned copy of the BloodHound Query Library that Pathwarden
# ships as prepared queries, in crates\pathwarden-core\queries\:
#   Queries.json  the library's Active Directory queries, as the release's
#                 Queries.json has them (Azure-only queries are left out)
#   LICENSE       the library's MIT license, from the same release tag
#   SOURCE        the release tag, the sha256 of the downloaded file (checked
#                 against the digest GitHub gives for the release asset) and
#                 the sha256 of the Queries.json written here
# It also writes the release tag into THIRD-PARTY-NOTICES.md and
# docs\running.md.
#
# Run it at release time, before scripts\package.ps1. Pathwarden never
# fetches the library at build time or at run time.
#
#   powershell -NoProfile -File scripts\update-queries.ps1 [-Tag queries-YYYY-MM-DD]
#
# Without -Tag it takes the library's latest queries-* release. It prints the
# queries added, removed and changed, with the Cypher of each added query and
# a line diff of each changed one. Then run the prepared-queries test
# (cargo test -p pathwarden-ui --test prepared): it says which new queries
# Pathwarden can't run yet, with the lines for unsupported.toml.
param([string]$Tag)
$ErrorActionPreference = 'Stop'
$repo = 'SpecterOps/BloodHoundQueryLibrary'
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root 'crates\pathwarden-core\queries'

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'The GitHub CLI (gh) is needed.' }
if (-not $Tag) {
    $Tag = (& gh release list -R $repo --limit 50 --json tagName --jq '.[].tagName' |
        Where-Object { $_ -like 'queries-*' } | Sort-Object -Descending | Select-Object -First 1)
    if (-not $Tag) { throw "No queries-* release found in $repo." }
}
if ($Tag -notmatch '^queries-\d{4}-\d{2}-\d{2}$') { throw "Not a library release tag: $Tag" }

# A fresh, empty folder for the download.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("pw-queries-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $tmp | Out-Null
try {
    & gh release download $Tag -R $repo -p 'Queries.json' -D $tmp
    if ($LASTEXITCODE -ne 0) { throw "Could not download Queries.json of $Tag." }
    $file = Join-Path $tmp 'Queries.json'
    $sha = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLowerInvariant()
    # The digest GitHub keeps for the release asset: the download must match.
    $assets = & gh release view $Tag -R $repo --json assets
    if ($LASTEXITCODE -ne 0) { throw "Could not read the release assets of $Tag." }
    $digest = (($assets -join "`n") | ConvertFrom-Json).assets | Where-Object { $_.name -eq 'Queries.json' } |
        Select-Object -First 1 -ExpandProperty digest
    if (-not $digest) { throw "GitHub gives no digest for Queries.json in $Tag, so the download can't be checked." }
    if ($digest.Trim() -ne "sha256:$sha") {
        throw "Queries.json of $Tag doesn't match its release digest ($($digest.Trim()), downloaded sha256:$sha)."
    }
    $license = & gh api "repos/$repo/contents/LICENSE?ref=$Tag" --jq '.content'
    if ($LASTEXITCODE -ne 0) { throw "Could not read the library's LICENSE at $Tag." }
    $license = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($license -join '')))
    if ($license -notmatch '^MIT License' -or $license -notmatch 'Copyright \(c\) (\d{4}) SpecterOps') {
        throw "The library's license is no longer the MIT license Pathwarden's notice names. Check it before shipping."
    }
    $year = $Matches[1]

    # The shape Pathwarden reads.
    $all = Get-Content -Raw -Encoding UTF8 $file | ConvertFrom-Json
    if ($all -isnot [array] -or $all.Count -lt 1) { throw 'Queries.json is not a list of queries.' }
    $kept = New-Object System.Collections.Generic.List[string]
    $guids = @{}
    foreach ($q in $all) {
        foreach ($k in 'name', 'guid', 'platforms', 'category', 'query', 'revision') {
            if ($null -eq $q.$k) { throw "A query has no ${k}: $($q | ConvertTo-Json -Compress)" }
        }
        if ($q.guid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { throw "Not a GUID: $($q.guid)" }
        if ($guids.ContainsKey($q.guid)) { throw "Two queries have GUID $($q.guid)." }
        $guids[$q.guid] = 1
        if (@($q.platforms) -notcontains 'Active Directory') { continue }
        $o = [ordered]@{
            name             = [string]$q.name
            guid             = [string]$q.guid
            category         = [string]$q.category
            description      = $q.description
            query            = [string]$q.query
            revision         = [int]$q.revision
            resources        = @(@($q.resources) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
            acknowledgements = @(@($q.acknowledgements) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
        }
        $kept.Add((ConvertTo-Json -InputObject $o -Compress -Depth 4))
    }
    # Windows PowerShell escapes ' < > & as \u00xx: written plainly, so the
    # file reads as the library wrote it (a backslash before them stays).
    $text = "[`n" + ($kept -join ",`n") + "`n]`n"
    foreach ($p in @(@('0027', "'"), @('003c', '<'), @('003e', '>'), @('0026', '&'))) {
        $text = [regex]::Replace($text, '(?<!\\)((?:\\\\)*)\\u' + $p[0], { param($m) $m.Groups[1].Value + $p[1] }.GetNewClosure())
    }

    # What changed since the pinned copy.
    $old = @{}
    $oldFile = Join-Path $dest 'Queries.json'
    if (Test-Path $oldFile) {
        foreach ($q in (Get-Content -Raw -Encoding UTF8 $oldFile | ConvertFrom-Json)) { $old[$q.guid] = $q }
    }
    $new = $text | ConvertFrom-Json
    $seen = @{}
    $lines = { param($s) @(([string]$s) -split "`r?`n") }
    foreach ($q in $new) {
        $seen[$q.guid] = 1
        if (-not $old.ContainsKey($q.guid)) {
            Write-Output "added    $($q.guid)  $($q.name)"
            foreach ($l in (& $lines $q.query)) { Write-Output "    + $l" }
        }
        elseif ($old[$q.guid].revision -ne $q.revision -or $old[$q.guid].query -ne $q.query) {
            Write-Output "changed  $($q.guid)  $($q.name) (revision $($old[$q.guid].revision) to $($q.revision))"
            $d = Compare-Object (& $lines $old[$q.guid].query) (& $lines $q.query) -SyncWindow 1000
            foreach ($x in $d) {
                $mark = if ($x.SideIndicator -eq '=>') { '+' } else { '-' }
                Write-Output "    $mark $($x.InputObject)"
            }
        }
    }
    foreach ($g in $old.Keys) { if (-not $seen.ContainsKey($g)) { Write-Output "removed  $g  $($old[$g].name)" } }

    $utf8 = New-Object Text.UTF8Encoding $false
    New-Item -ItemType Directory -Force $dest | Out-Null
    $bytes = $utf8.GetBytes($text)
    [IO.File]::WriteAllBytes((Join-Path $dest 'Queries.json'), $bytes)
    $hasher = [Security.Cryptography.SHA256]::Create()
    $shipped = -join ($hasher.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
    [IO.File]::WriteAllText((Join-Path $dest 'LICENSE'), ($license -replace "`r`n", "`n"), $utf8)
    $source = @"
# The pinned copy of the BloodHound Query Library: scripts\update-queries.ps1 writes this folder.
library = "BloodHound Query Library"
url = "https://github.com/$repo"
tag = "$Tag"
sha256 = "$sha"
shipped_sha256 = "$shipped"
copyright = "$year SpecterOps"
kept = "$($new.Count) of $($all.Count) queries: those for Active Directory"
"@
    [IO.File]::WriteAllText((Join-Path $dest 'SOURCE'), ($source -replace "`r`n", "`n") + "`n", $utf8)
    # The release named where the notices and docs name it.
    foreach ($rel in 'THIRD-PARTY-NOTICES.md', 'docs\running.md') {
        $p = Join-Path $root $rel
        $t = [IO.File]::ReadAllText($p)
        $t2 = [regex]::Replace($t, 'queries-\d{4}-\d{2}-\d{2}', $Tag)
        if ($t2 -ne $t) { [IO.File]::WriteAllText($p, $t2, $utf8) }
    }
    Write-Output "Wrote $($new.Count) of $($all.Count) queries from $Tag (sha256 $sha) to $dest."
    Write-Output 'Next: cargo test -p pathwarden-ui --test prepared, and update unsupported.toml and findings.toml as it says.'
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
