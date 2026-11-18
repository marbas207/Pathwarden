<#
.SYNOPSIS
A helper for writing Pathwarden finding actions in PowerShell.

.DESCRIPTION
A finding action is a program Pathwarden runs for one finding when someone
asks (docs/actions.md). This module speaks the protocol for you: it reads
the request, answers describe, calls your script block for run, prints
progress lines, and writes a checked result to the file Pathwarden names.
An error becomes a failed run with a plain message.

Works in Windows PowerShell 5.1 and PowerShell 7. Copy this file next to
your action, then:

    $ErrorActionPreference = 'Stop'
    Import-Module (Join-Path $PSScriptRoot 'PathwardenAction.psm1')

    $actions = @(
        @{ id = 'hello'; label = 'Say hello'; sends = 'Nothing: it only answers.' }
    )

    Invoke-PathwardenAction -Describe $actions -Handlers @{
        hello = {
            param($Request)
            Write-PathwardenProgress 'Saying hello'
            New-PathwardenResult -Message "Hello from $($Request.finding.fingerprint)."
        }
    }

Everything here follows pathwarden.action-*.v1. The caps are the ones
Pathwarden applies (crates/pathwarden-core/src/actions.rs), so what this
module writes is never cut or refused on the other side.
#>

Set-StrictMode -Version 2.0

$script:RequestSchema = 'pathwarden.action-request.v1'
$script:DescribeSchema = 'pathwarden.action-describe.v1'
$script:ResultSchema = 'pathwarden.action-result.v1'
$script:Version = '1.0.0'

# The caps Pathwarden applies (actions.rs MAX_* constants).
$script:Caps = @{
    Message = 2000; Label = 80; Links = 5; Records = 5; RecordText = 200
    Fields = 20; Field = 200; Name = 60; Url = 2048; Line = 500
}

# Windows PowerShell 5.1 may not offer TLS 1.2 by default.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$script:Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:Out = $null

function Get-Out {
    # Pathwarden reads stdout as UTF-8; the console's code page would
    # garble names. One writer, flushed after every line, so progress
    # shows as it happens.
    if ($null -eq $script:Out) {
        $script:Out = New-Object System.IO.StreamWriter([Console]::OpenStandardOutput(), $script:Utf8)
        $script:Out.AutoFlush = $true
    }
    $script:Out
}

function Get-CleanText {
    # Text as Pathwarden keeps it: tabs as spaces, control and bidi
    # characters dropped (line breaks kept with -Lines), trimmed, cut to
    # -Cap characters with an ellipsis.
    param([AllowNull()][object]$Text, [int]$Cap, [switch]$Lines)
    if ($null -eq $Text) { return '' }
    $s = ([string]$Text).Replace("`r`n", "`n").Replace("`t", ' ')
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $s.ToCharArray()) {
        $code = [int]$c
        $bidi = ($code -ge 0x202A -and $code -le 0x202E) -or ($code -ge 0x2066 -and $code -le 0x2069) -or $code -eq 0x200E -or $code -eq 0x200F -or $code -eq 0x061C
        if ($Lines -and $c -eq "`n") { [void]$sb.Append($c); continue }
        if ([char]::IsControl($c) -or $bidi) { continue }
        [void]$sb.Append($c)
    }
    $t = $sb.ToString().Trim()
    if ($t.Length -le $Cap) { return $t }
    return $t.Substring(0, $Cap - 1) + [char]0x2026
}

function Get-HttpsProblem {
    # Why Pathwarden would leave $Url out of a result, or $null.
    param([AllowNull()][object]$Url)
    if ($Url -isnot [string]) { return 'must be text' }
    $s = $Url.Trim()
    if ($s.Length -gt $script:Caps.Url) { return 'is longer than 2,048 characters' }
    foreach ($c in $s.ToCharArray()) {
        if ([char]::IsWhiteSpace($c) -or [char]::IsControl($c)) { return 'holds a space or a control character' }
    }
    if ($s.Length -lt 8 -or $s.Substring(0, 8).ToLowerInvariant() -ne 'https://') { return 'must start with https://' }
    $authority = ($s.Substring(8) -split '[/?#]', 2)[0]
    if ($authority.Contains('@')) { return 'must not hold a user name or password' }
    $hostPart = $authority
    $i = $authority.LastIndexOf(':')
    if ($i -gt 0 -and $authority.Substring($i + 1) -match '^\d*$') { $hostPart = $authority.Substring(0, $i) }
    if (-not $hostPart -or $hostPart -match '[\\<>"]') { return 'has no host' }
    return $null
}

function Get-Field {
    # A key of a hashtable or a property of an object, or $null.
    param([AllowNull()][object]$From, [string]$Name)
    if ($null -eq $From) { return $null }
    if ($From -is [System.Collections.IDictionary]) {
        if ($From.Contains($Name)) { return $From[$Name] }
        return $null
    }
    $p = $From.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Write-PathwardenProgress {
    <#
    .SYNOPSIS
    Prints one progress line. Pathwarden shows it while the action runs and
    keeps the latest 200, each cut to 500 characters.
    #>
    param([Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$Line)
    process {
        foreach ($part in ($Line -split "`r?`n")) {
            $t = Get-CleanText $part $script:Caps.Line
            if ($t) { (Get-Out).WriteLine($t) }
        }
    }
}

function Write-PathwardenNote {
    <#
    .SYNOPSIS
    Writes a line to stderr: kept for Show details, never shown as progress.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Line)
    [Console]::Error.WriteLine($Line)
}

function New-PathwardenLink {
    <#
    .SYNOPSIS
    A link the result card offers. It must be https://.
    #>
    param([Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)][string]$Url)
    [ordered]@{ label = $Label; url = $Url }
}

function New-PathwardenRecord {
    <#
    .SYNOPSIS
    Something the action created or looks after, such as a ticket. It is
    saved on the finding. A follow-up returns the same -Id to update it;
    -Open says it is still open in the other system.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [string]$Kind, [string]$Label, [string]$Number, [string]$Url, [string]$Status,
        [switch]$Open,
        [System.Collections.IDictionary]$Fields
    )
    $r = [ordered]@{ id = $Id; open = [bool]$Open }
    foreach ($k in 'Kind', 'Label', 'Number', 'Url', 'Status') {
        $v = Get-Variable -Name $k -ValueOnly
        if ($v) { $r[$k.ToLowerInvariant()] = $v }
    }
    if ($Fields -and $Fields.Count) { $r.fields = $Fields }
    $r
}

function New-PathwardenResult {
    <#
    .SYNOPSIS
    The result of a run: -Message, -Links, -Records, and -Failed when it
    didn't work. Make it the last thing your handler outputs.
    #>
    param(
        [Parameter(Position = 0)][AllowEmptyString()][string]$Message = '',
        [switch]$Failed,
        [object[]]$Links = @(),
        [object[]]$Records = @()
    )
    $r = [pscustomobject]@{ ok = -not $Failed; message = $Message; links = @($Links); records = @($Records) }
    $r.PSObject.TypeNames.Insert(0, 'Pathwarden.ActionResult')
    $r
}

function Get-PathwardenSetting {
    <#
    .SYNOPSIS
    A setting of the [[action]] block. With -Required, a missing one fails
    the run with a message that names it.
    #>
    param([Parameter(Mandatory)][object]$Request, [Parameter(Mandatory)][string]$Name, [object]$Default = $null, [switch]$Required)
    $v = Get-Field (Get-Field $Request 'settings') $Name
    if ($null -eq $v -or $v -eq '') {
        if ($Required) { throw "Set $Name in this action's settings." }
        return $Default
    }
    $v
}

function Get-PathwardenSecret {
    <#
    .SYNOPSIS
    The value of the environment variable that setting <Name>_env names.
    Secrets never go in the settings: Pathwarden passes only the
    variables *_env settings name.
    #>
    param([Parameter(Mandatory)][object]$Request, [Parameter(Mandatory)][string]$Name, [switch]$Optional)
    $var = Get-Field (Get-Field $Request 'settings') "$($Name)_env"
    if (-not $var) {
        if ($Optional) { return $null }
        throw "Set $($Name)_env in this action's settings to the name of the environment variable that holds the $Name."
    }
    $value = [Environment]::GetEnvironmentVariable([string]$var)
    if (-not $value) {
        if ($Optional) { return $null }
        throw "The environment variable $var (named by $($Name)_env) isn't set for this account."
    }
    $value
}

function Test-Loopback([string]$HostName) {
    $h = $HostName.Trim('[', ']')
    if ($h -eq 'localhost') { return $true }
    $ip = $null
    if ([Net.IPAddress]::TryParse($h, [ref]$ip)) { return [Net.IPAddress]::IsLoopback($ip) }
    return $false
}

function Invoke-PathwardenHttp {
    <#
    .SYNOPSIS
    Sends one HTTPS request and returns the answer, parsed from JSON. An
    answer of 400 or above fails the run, with the status in the message.

    .DESCRIPTION
    - -Body is sent as JSON; -Bearer as Authorization: Bearer ...
    - Certificates are checked against the Windows certificate store, never
      turned off.
    - http:// is refused, except to this computer (localhost, 127.0.0.1,
      ::1), for a test server.
    - On a dry run, only GET and HEAD are sent; anything else fails the
      run, so a dry run can't change anything by mistake.
    #>
    param(
        [Parameter(Mandatory)][object]$Request,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body = $null,
        [string]$Bearer,
        [System.Collections.IDictionary]$Headers = @{},
        [int]$TimeoutSec = 30
    )
    $Method = $Method.ToUpperInvariant()
    $u = $null
    if (-not [Uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$u)) { throw "$Uri isn't a full address." }
    $shown = $u.GetLeftPart([UriPartial]::Path)
    $okScheme = ($u.Scheme -eq 'https') -or ($u.Scheme -eq 'http' -and (Test-Loopback $u.Host))
    if (-not $okScheme) { throw "$shown must start with https:// (http:// only to this computer, for testing)." }
    if ((Get-Field $Request 'dry_run') -and $Method -notin 'GET', 'HEAD') {
        throw "Dry run: $Method $shown wasn't sent, because a dry run changes nothing. Return before sending it when `$Request.dry_run is true."
    }
    $h = @{ Accept = 'application/json'; 'User-Agent' = "pathwarden-action/$script:Version" }
    foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
    if ($Bearer) { $h.Authorization = "Bearer $Bearer" }
    $call = @{ Method = $Method; Uri = $u; Headers = $h; TimeoutSec = $TimeoutSec; UseBasicParsing = $true; ErrorAction = 'Stop' }
    if ($null -ne $Body) {
        $call.Body = $script:Utf8.GetBytes((ConvertTo-Json -InputObject $Body -Depth 20 -Compress))
        $call.ContentType = 'application/json; charset=utf-8'
    }
    try {
        Invoke-RestMethod @call
    } catch {
        $status = $null
        $resp = $_.Exception.PSObject.Properties['Response']
        if ($resp -and $resp.Value) { try { $status = [int]$resp.Value.StatusCode } catch { } }
        if ($status) {
            Write-PathwardenNote "$Method $shown answered $status`n$($_.ErrorDetails)"
            throw "$Method $shown answered $status."
        }
        throw "Couldn't reach $($shown): $($_.Exception.Message)"
    }
}

function ConvertTo-PathwardenResult {
    <#
    .SYNOPSIS
    A handler's answer as Pathwarden would keep it (schema added, text
    cleaned and capped, links https:// only), and notes on what changed.
    Returns @{ Result = ...; Notes = @(...) }.
    #>
    param([AllowNull()][object]$Answer)
    $notes = New-Object System.Collections.Generic.List[string]
    $c = $script:Caps
    $message = Get-CleanText (Get-Field $Answer 'message') $c.Message -Lines
    if (([string](Get-Field $Answer 'message')).Trim().Length -gt $c.Message) {
        $notes.Add("message is longer than $($c.Message) characters; it was cut")
    }
    $links = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($l in @(Get-Field $Answer 'links')) {
        if ($null -eq $l) { continue }
        if ($i -ge $c.Links) { $notes.Add("links has more than $($c.Links) links; the rest were left out"); break }
        $why = Get-HttpsProblem (Get-Field $l 'url')
        $label = Get-CleanText (Get-Field $l 'label') $c.Label
        if ($why) { $notes.Add("links[$i].url $why; the link was left out") }
        elseif (-not $label) { $notes.Add("links[$i].label is missing") }
        else { $links.Add([ordered]@{ label = $label; url = ([string](Get-Field $l 'url')).Trim() }) }
        $i++
    }
    $records = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $i = 0
    foreach ($r in @(Get-Field $Answer 'records')) {
        if ($null -eq $r) { continue }
        if ($i -ge $c.Records) { $notes.Add("records has more than $($c.Records) records; the rest were left out"); break }
        $at = "records[$i]"
        $i++
        $id = Get-CleanText (Get-Field $r 'id') $c.RecordText
        if (-not $id -or $id.EndsWith([string][char]0x2026)) { $notes.Add("$at.id is missing or too long; the record was left out"); continue }
        if ($seen.ContainsKey($id)) { $notes.Add("$at.id '$id' is there twice; the second was left out"); continue }
        $seen[$id] = $true
        $kept = [ordered]@{ id = $id; open = [bool](Get-Field $r 'open') }
        foreach ($k in 'kind', 'label', 'number', 'status') {
            $v = Get-Field $r $k
            if ($null -ne $v -and $v -ne '') { $kept[$k] = Get-CleanText $v $c.RecordText }
        }
        $url = Get-Field $r 'url'
        if ($url) {
            $why = Get-HttpsProblem $url
            if ($why) { $notes.Add("$at.url $why; it was left out") } else { $kept.url = ([string]$url).Trim() }
        }
        $fields = Get-Field $r 'fields'
        if ($fields) {
            $f = [ordered]@{}
            $names = New-Object System.Collections.Generic.List[string]
            $values = New-Object System.Collections.Generic.List[object]
            if ($fields -is [System.Collections.IDictionary]) {
                foreach ($k in $fields.Keys) { $names.Add([string]$k); $values.Add($fields[$k]) }
            } else {
                foreach ($p in $fields.PSObject.Properties) { $names.Add($p.Name); $values.Add($p.Value) }
            }
            for ($j = 0; $j -lt $names.Count; $j++) {
                if ($f.Count -ge $c.Fields) { $notes.Add("$at.fields has more than $($c.Fields) fields; the rest were left out"); break }
                $name = Get-CleanText $names[$j] $c.Name
                if (-not $name -or $f.Contains($name)) { $notes.Add("$at.fields name '$name' is empty, too long or there twice; it was left out"); continue }
                $v = $values[$j]
                if ($v -is [bool]) { $v = if ($v) { 'true' } else { 'false' } }
                $f[$name] = Get-CleanText $v $c.Field
            }
            if ($f.Count) { $kept.fields = $f }
        }
        $records.Add($kept)
    }
    $ok = [bool](Get-Field $Answer 'ok')
    @{
        Result = [ordered]@{ schema = $script:ResultSchema; ok = $ok; message = $message; links = $links.ToArray(); records = $records.ToArray() }
        Notes  = $notes.ToArray()
    }
}

function Write-Answer([string]$Path, [object]$Doc) {
    $json = ConvertTo-Json -InputObject $Doc -Depth 20
    if ($Path) {
        [IO.File]::WriteAllText($Path, $json, $script:Utf8)
    } else {
        Write-PathwardenNote 'PATHWARDEN_ACTION_RESULT isn''t set, so the answer goes to stdout:'
        (Get-Out).WriteLine($json)
    }
}

function Read-Request {
    $reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), $script:Utf8)
    $reader.ReadToEnd()
}

function Invoke-PathwardenAction {
    <#
    .SYNOPSIS
    Runs the action program: reads the request from stdin and writes the
    answer to the file named in PATHWARDEN_ACTION_RESULT.

    .PARAMETER Describe
    The actions, as hashtables (docs/actions.md), or a script block that
    gets the settings and returns them. The schema is added.

    .PARAMETER Handlers
    A script block per action ID. It gets the request (param($Request))
    and outputs New-PathwardenResult last. Without one, a run says "Done."
    (or "Dry run: nothing was changed."); a string output alone is the
    message. Any other output is shown as progress lines. A thrown error
    fails the run with its message; its position goes to stderr.

    .PARAMETER NoExit
    Return the exit code instead of exiting (for tests). -RequestText and
    -ResultPath replace stdin and PATHWARDEN_ACTION_RESULT.
    #>
    param(
        [Parameter(Mandatory)][object]$Describe,
        [Parameter(Mandatory)][hashtable]$Handlers,
        [string]$RequestText,
        [string]$ResultPath,
        [switch]$NoExit
    )
    if (-not $PSBoundParameters.ContainsKey('ResultPath')) { $ResultPath = $env:PATHWARDEN_ACTION_RESULT }
    if (-not $PSBoundParameters.ContainsKey('RequestText')) { $RequestText = Read-Request }
    $code = 1
    $text = ([string]$RequestText).TrimStart([char]0xFEFF)
    $req = $null
    try {
        if ($text.Trim()) { $req = ConvertFrom-Json -InputObject $text }
    } catch {
        Write-Answer $ResultPath ([ordered]@{ schema = $script:ResultSchema; ok = $false; message = "The request couldn't be read: $($_.Exception.Message)" })
        return (Stop-Run 1 $NoExit)
    }
    $schema = Get-Field $req 'schema'
    if ($schema -and $schema -ne $script:RequestSchema) {
        # Within v1 fields are only added; another schema is a change this
        # program doesn't know.
        Write-Answer $ResultPath ([ordered]@{ schema = $script:ResultSchema; ok = $false; message = "This program reads $script:RequestSchema, not $($schema): update it." })
        return (Stop-Run 1 $NoExit)
    }
    $kind = [string](Get-Field $req 'kind')
    if (-not $kind) { $kind = [string]$env:PATHWARDEN_ACTION_REQUEST }
    if ($kind -eq 'describe') {
        $actions = if ($Describe -is [scriptblock]) { & $Describe (Get-Field $req 'settings') } else { $Describe }
        foreach ($a in @($actions)) {
            $id = Get-Field $a 'id'
            if (-not $Handlers.ContainsKey([string]$id)) { Write-PathwardenNote "describe: action '$id' has no handler" }
            if (-not (Get-Field $a 'sends')) { Write-PathwardenNote "describe: action '$id': sends is missing: say in plain words what leaves the computer" }
        }
        Write-Answer $ResultPath ([ordered]@{ schema = $script:DescribeSchema; actions = @($actions) })
        return (Stop-Run 0 $NoExit)
    }
    if ($kind -ne 'run') {
        Write-Answer $ResultPath ([ordered]@{ schema = $script:ResultSchema; ok = $false; message = "Unknown request kind '$kind'." })
        return (Stop-Run 1 $NoExit)
    }
    $action = [string](Get-Field $req 'action')
    try {
        if (-not $Handlers.ContainsKey($action)) { throw "This program has no action '$action'." }
        $output = @(& $Handlers[$action] $req)
        $answer = $null
        $lastText = $null
        foreach ($o in $output) {
            if ($null -eq $o) { continue }
            if ($o.PSObject.TypeNames -contains 'Pathwarden.ActionResult') { $answer = $o; continue }
            if ($o -is [System.Collections.IDictionary] -and $o.Contains('ok')) { $answer = $o; continue }
            $lastText = [string]$o
            Write-PathwardenProgress $lastText
        }
        if ($null -eq $answer) {
            $msg = if ($lastText) { $lastText } elseif (Get-Field $req 'dry_run') { 'Dry run: nothing was changed.' } else { 'Done.' }
            $answer = New-PathwardenResult -Message $msg
        }
        $clean = ConvertTo-PathwardenResult $answer
        foreach ($n in $clean.Notes) { Write-PathwardenNote "result: $n" }
        $result = $clean.Result
        if ($result.ok) { $code = 0 }
    } catch {
        Write-PathwardenNote ($_.ScriptStackTrace)
        $msg = $_.Exception.Message
        if (-not $msg) { $msg = "It didn't work." }
        $result = (ConvertTo-PathwardenResult (New-PathwardenResult -Failed -Message $msg)).Result
    }
    Write-Answer $ResultPath $result
    return (Stop-Run $code $NoExit)
}

function Stop-Run([int]$Code, [bool]$NoExit) {
    if ($null -ne $script:Out) { $script:Out.Flush() }
    if ($NoExit) { return $Code }
    exit $Code
}

Export-ModuleMember -Function Invoke-PathwardenAction, Write-PathwardenProgress, Write-PathwardenNote, New-PathwardenResult, New-PathwardenLink, New-PathwardenRecord, Get-PathwardenSetting, Get-PathwardenSecret, Invoke-PathwardenHttp, ConvertTo-PathwardenResult
