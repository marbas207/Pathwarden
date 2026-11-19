# Tests for PathwardenAction.psm1, without Pester. Windows PowerShell 5.1
# and PowerShell 7:
#
#     powershell -NoProfile -ExecutionPolicy Bypass -File examples\actions\PathwardenAction.Tests.ps1
#
# Exits 1 when a test fails.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PathwardenAction.psm1') -Force

$script:failures = 0
$script:count = 0
function Test([string]$Name, [scriptblock]$Body) {
    $script:count++
    try { & $Body; Write-Host "ok   $Name" }
    catch { $script:failures++; Write-Host "FAIL $Name`n     $($_.Exception.Message)" }
}
function Assert-Equal($Expected, $Actual, [string]$What = 'value') {
    if ($Expected -ne $Actual) { throw "$($What): expected '$Expected', got '$Actual'" }
}
function Assert-True($Condition, [string]$What) { if (-not $Condition) { throw $What } }

$dir = Join-Path ([IO.Path]::GetTempPath()) ("pw-action-tests-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $dir | Out-Null
$resultPath = Join-Path $dir 'result.json'

$actions = @(
    @{ id = 'open'; label = 'Open a ticket'; sends = "The finding's title."
       inputs = @(@{ id = 'note'; label = 'Note'; type = 'textarea' }); once = $true; follow_ups = @('status') },
    @{ id = 'status'; label = 'Check status'; for = 'record'; sends = "The ticket's number." }
)

function New-Request([hashtable]$Over = @{}) {
    $r = [ordered]@{
        schema = 'pathwarden.action-request.v1'; kind = 'run'; action = 'open'
        inputs = @{ note = 'hi' }; dry_run = $false; settings = @{}
        run = @{ run_id = 'r'; domains = @('SCALE.LOCAL'); pathwarden = '1.0.0' }
        finding = @{ fingerprint = 'PW-001-0000000000000000'; rule = 'PW-001'; title = 'A sample'; status = 'open' }
        record = $null; requested_by = @{ by = 'SCALE\analyst'; on = 'PW-DEMO-01' }
    }
    foreach ($k in $Over.Keys) { $r[$k] = $Over[$k] }
    ConvertTo-Json -InputObject $r -Depth 10
}

function Invoke-Case([string]$Request, [hashtable]$Handlers, $Describe = $actions) {
    Remove-Item $resultPath -ErrorAction SilentlyContinue
    # What the module writes to stderr (Show details) is kept, not shown.
    $stderr = [Console]::Error
    $script:details = New-Object IO.StringWriter
    [Console]::SetError($script:details)
    try {
        $code = Invoke-PathwardenAction -Describe $Describe -Handlers $Handlers -RequestText $Request -ResultPath $resultPath -NoExit
    } finally {
        [Console]::SetError($stderr)
    }
    $answer = Get-Content $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
    @{ Code = $code; Answer = $answer }
}

Test 'describe writes the actions with the schema' {
    $r = Invoke-Case '{"schema":"pathwarden.action-request.v1","kind":"describe","settings":{}}' @{ open = {}; status = {} }
    Assert-Equal 0 $r.Code 'exit code'
    Assert-Equal 'pathwarden.action-describe.v1' $r.Answer.schema 'schema'
    Assert-Equal 'open,status' (($r.Answer.actions | ForEach-Object { $_.id }) -join ',') 'ids'
    # A one-element list stays a list.
    Assert-True ($r.Answer.actions[0].inputs -is [array]) 'inputs is a list'
    Assert-Equal 'status' $r.Answer.actions[0].follow_ups[0] 'follow-up'
}

Test 'describe can depend on the settings' {
    $d = { param($settings) if ($settings.full) { $actions } else { , $actions[0] } }
    $r = Invoke-Case '{"kind":"describe","settings":{"full":false}}' @{ open = {} } $d
    Assert-Equal 1 @($r.Answer.actions).Count 'actions'
}

Test 'a handler gets the request and its result is written' {
    $h = @{ open = {
        param($Request)
        Write-PathwardenProgress 'Opening a ticket'
        $rec = New-PathwardenRecord -Id 't-1' -Number 'T-1' -Status 'Open' -Open -Url 'https://desk.example.com/T-1' -Fields ([ordered]@{ Queue = 'Identity' })
        New-PathwardenResult "Opened T-1 for $($Request.finding.fingerprint) ($($Request.inputs.note))." -Records @($rec) -Links @(New-PathwardenLink 'Open' 'https://desk.example.com/T-1')
    } }
    $r = Invoke-Case (New-Request) $h
    Assert-Equal 0 $r.Code 'exit code'
    Assert-Equal $true $r.Answer.ok 'ok'
    Assert-Equal 'Opened T-1 for PW-001-0000000000000000 (hi).' $r.Answer.message 'message'
    Assert-True ($r.Answer.records -is [array]) 'records is a list'
    Assert-Equal 'T-1' $r.Answer.records[0].number 'number'
    Assert-Equal $true $r.Answer.records[0].open 'open'
    Assert-Equal 'Identity' $r.Answer.records[0].fields.Queue 'field'
    Assert-Equal 'https://desk.example.com/T-1' $r.Answer.links[0].url 'link'
}

Test 'no result is Done, or nothing changed on a dry run' {
    Assert-Equal 'Done.' (Invoke-Case (New-Request) @{ open = {} }).Answer.message 'message'
    Assert-Equal 'Dry run: nothing was changed.' (Invoke-Case (New-Request @{ dry_run = $true }) @{ open = {} }).Answer.message 'dry run'
    Assert-Equal 'Sent.' (Invoke-Case (New-Request) @{ open = { 'Sent.' } }).Answer.message 'a string'
}

Test 'a thrown error is a failed run with its message' {
    $r = Invoke-Case (New-Request) @{ open = { throw 'The desk said no: 403 Forbidden.' } }
    Assert-True ($script:details.ToString() -like "*PathwardenAction.Tests.ps1*") "the error's position goes to stderr"
    Assert-Equal 1 $r.Code 'exit code'
    Assert-Equal $false $r.Answer.ok 'ok'
    Assert-Equal 'The desk said no: 403 Forbidden.' $r.Answer.message 'message'
}

Test 'an unknown action fails' {
    $r = Invoke-Case (New-Request @{ action = 'nope' }) @{ open = {} }
    Assert-Equal "This program has no action 'nope'." $r.Answer.message 'message'
}

Test 'another request schema fails' {
    $r = Invoke-Case (New-Request @{ schema = 'pathwarden.action-request.v2' }) @{ open = {} }
    Assert-Equal $false $r.Answer.ok 'ok'
    Assert-True ($r.Answer.message -like '*not pathwarden.action-request.v2*') $r.Answer.message
}

Test 'a broken request fails' {
    $r = Invoke-Case '{not json' @{}
    Assert-Equal $false $r.Answer.ok 'ok'
    Assert-True ($r.Answer.message -like "The request couldn't be read*") $r.Answer.message
}

Test 'text, links, records and fields are capped as Pathwarden does' {
    $many = 1..7 | ForEach-Object {
        $f = [ordered]@{}; 1..25 | ForEach-Object { $f["f$_"] = 'v' * 300 }
        New-PathwardenRecord -Id "r$_" -Fields $f
    }
    $answer = New-PathwardenResult ("a" + [char]0x202E + [char]7 + "b`r`nc" + ('x' * 3000)) -Records $many -Links @(
        (New-PathwardenLink 'A' 'http://x.example'), (New-PathwardenLink 'B' 'https://u:p@x.example'), (New-PathwardenLink 'C' 'https://x.example/c'))
    $c = ConvertTo-PathwardenResult $answer
    Assert-Equal 2000 $c.Result.message.Length 'message length'
    Assert-True ($c.Result.message.StartsWith("ab`nc")) 'cleaned message'
    Assert-Equal 1 @($c.Result.links).Count 'links'
    Assert-Equal 5 @($c.Result.records).Count 'records'
    Assert-Equal 20 $c.Result.records[0].fields.Count 'fields'
    Assert-Equal 200 $c.Result.records[0].fields['f1'].Length 'field length'
    Assert-True ($c.Notes -contains 'links[0].url must start with https://; the link was left out') ($c.Notes -join '; ')
    Assert-True ($c.Notes -contains 'links[1].url must not hold a user name or password; the link was left out') ($c.Notes -join '; ')
}

Test 'secrets come from the variable an _env setting names' {
    $req = New-Request @{ settings = @{ token_env = 'PW_TEST_TOKEN' } } | ConvertFrom-Json
    $env:PW_TEST_TOKEN = 's3cret'
    Assert-Equal 's3cret' (Get-PathwardenSecret -Request $req -Name token) 'secret'
    Remove-Item Env:PW_TEST_TOKEN
    $msg = try { Get-PathwardenSecret -Request $req -Name token; '' } catch { $_.Exception.Message }
    Assert-Equal "The environment variable PW_TEST_TOKEN (named by token_env) isn't set for this account." $msg 'missing'
    $none = New-Request | ConvertFrom-Json
    Assert-Equal $null (Get-PathwardenSecret -Request $none -Name token -Optional) 'optional'
    $msg = try { Get-PathwardenSetting -Request $none -Name base_url -Required; '' } catch { $_.Exception.Message }
    Assert-Equal "Set base_url in this action's settings." $msg 'setting'
}

Test 'http is refused but to this computer, and a dry run sends only reads' {
    $req = New-Request @{ dry_run = $true } | ConvertFrom-Json
    $msg = try { Invoke-PathwardenHttp -Request $req -Method Get -Uri 'http://desk.example.com/api'; '' } catch { $_.Exception.Message }
    Assert-True ($msg -like '*must start with https://*') $msg
    $msg = try { Invoke-PathwardenHttp -Request $req -Method Post -Uri 'https://desk.example.com/api?key=hidden' -Body @{}; '' } catch { $_.Exception.Message }
    Assert-True ($msg -like "Dry run: POST https://desk.example.com wasn't sent*") $msg
}

Test 'messages show only the scheme, host and port, and no secret' {
    $req = New-Request @{ dry_run = $true } | ConvertFrom-Json
    $msg = try { Invoke-PathwardenHttp -Request $req -Method Post -Uri 'https://hooks.example.com:8443/services/T0/B0/SECRET?k=v' -Body @{}; '' } catch { $_.Exception.Message }
    Assert-True ($msg -like 'Dry run: POST https://hooks.example.com:8443 wasn''t sent*') $msg
    $msg = try { Invoke-PathwardenHttp -Request $req -Method Get -Uri 'ftp://hooks.example.com/services/SECRET'; '' } catch { $_.Exception.Message }
    Assert-True ($msg -notlike '*SECRET*' -and $msg -like '*must start with https://*') $msg
    $msg = try { Invoke-PathwardenHttp -Request $req -Method Get -Uri 'hooks.example.com/services/SECRET'; '' } catch { $_.Exception.Message }
    Assert-True ($msg -notlike '*SECRET*') $msg

    $env:PW_TEST_HOOK = 'https://hooks.example.com/services/T0/B0/hook-7c6b5a4d3e2f'
    try {
        $h = @{ open = {
            param($Request)
            $url = Get-PathwardenSecret -Request $Request -Name webhook
            Write-PathwardenProgress "Posting to $url"
            throw "It went wrong at $url"
        } }
        $r = Invoke-Case (New-Request @{ settings = @{ webhook_env = 'PW_TEST_HOOK' } }) $h
        Assert-Equal 'It went wrong at [hidden]' $r.Answer.message 'message'
        Assert-True ($script:details.ToString() -notlike '*hook-7c6b5a4d3e2f*') 'stderr'
    } finally {
        Remove-Item Env:PW_TEST_HOOK
    }
}

Test 'a redirect is followed only to the same address' {
    # A small HTTP server on this computer, in a runspace.
    $state = [hashtable]::Synchronized(@{ Port = 0; Seen = [Collections.ArrayList]::Synchronized((New-Object Collections.ArrayList)) })
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript({
        param($state)
        $l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
        $l.Start()
        $state.Listener = $l
        $state.Port = $l.LocalEndpoint.Port
        while ($true) {
            $c = $l.AcceptTcpClient()
            $s = $c.GetStream()
            $r = New-Object IO.StreamReader($s)
            $first = $r.ReadLine()
            $auth = $null
            while (($line = $r.ReadLine())) { if ($line -like 'Authorization:*') { $auth = $line.Substring(14).Trim() } }
            $path = $first.Split(' ')[1]
            [void]$state.Seen.Add("$path $auth")
            $resp = switch ($path) {
                '/away' { "HTTP/1.1 302 Found`r`nLocation: http://127.0.0.1:1/secret/path`r`nContent-Length: 0`r`nConnection: close`r`n`r`n" }
                '/near' { "HTTP/1.1 302 Found`r`nLocation: /there`r`nContent-Length: 0`r`nConnection: close`r`n`r`n" }
                default { $b = '{"path":"' + $path + '","auth":"' + $auth + '"}'; "HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: $($b.Length)`r`nConnection: close`r`n`r`n$b" }
            }
            $bytes = [Text.Encoding]::ASCII.GetBytes($resp)
            $s.Write($bytes, 0, $bytes.Length)
            $s.Flush()
            $c.Close()
        }
    }).AddArgument($state)
    $async = $ps.BeginInvoke()
    try {
        for ($i = 0; $i -lt 100 -and -not $state.Port; $i++) { Start-Sleep -Milliseconds 50 }
        $base = "http://127.0.0.1:$($state.Port)"
        $req = New-Request | ConvertFrom-Json
        $got = Invoke-PathwardenHttp -Request $req -Method Get -Uri "$base/near" -Bearer 't'
        Assert-Equal '/there' $got.path 'followed'
        Assert-Equal 'Bearer t' $got.auth 'auth kept on the same address'
        $msg = try { Invoke-PathwardenHttp -Request $req -Method Get -Uri "$base/away" -Bearer 't'; '' } catch { $_.Exception.Message }
        Assert-True ($msg -like "*answered 302, a redirect to http://127.0.0.1:1, which wasn't followed*") $msg
        Assert-True ($msg -notlike '*/secret*') $msg
        Assert-Equal '/near Bearer t,/there Bearer t,/away Bearer t' ($state.Seen -join ',') 'requests sent'
    } finally {
        if ($state.Listener) { $state.Listener.Stop() }
        # Stop would wait for the blocked accept; the listener's Stop ends it.
        [void]$ps.BeginStop($null, $null)
    }
}

Test 'only a real true is open' {
    $c = ConvertTo-PathwardenResult ([pscustomobject]@{ ok = $true; message = ''; links = @(); records = @(
        @{ id = 'a'; open = 'yes' }, @{ id = 'b'; open = 1 }, @{ id = 'c'; open = $true }, @{ id = 'd' }) })
    Assert-Equal 'False,False,True,False' (($c.Result.records | ForEach-Object { $_.open }) -join ',') 'open'
    Assert-Equal 2 @($c.Notes | Where-Object { $_ -like '*.open must be true or false*' }).Count ($c.Notes -join '; ')
}

Test 'addresses and lengths are checked as Pathwarden does' {
    $bidi = 'https://x.example/a' + [char]0x202E + 'b'
    $long = 'https://x.example/' + ([string][char]0xE9 * 1100)
    $c = ConvertTo-PathwardenResult (New-PathwardenResult -Links @((New-PathwardenLink 'A' $bidi), (New-PathwardenLink 'B' $long), (New-PathwardenLink 'C' 'https://x.example/c')))
    Assert-Equal 1 @($c.Result.links).Count 'links'
    Assert-True ($c.Notes -contains 'links[0].url holds a space or a control character; the link was left out') ($c.Notes -join '; ')
    Assert-True ($c.Notes -contains 'links[1].url is longer than 2,048 characters; the link was left out') ($c.Notes -join '; ')
    # A surrogate pair is one character, and never split.
    $face = [char]::ConvertFromUtf32(0x1F600)
    $m = (ConvertTo-PathwardenResult (New-PathwardenResult ($face * 2500))).Result.message
    Assert-Equal (1999 * 2 + 1) $m.Length 'message length in UTF-16 units'
    Assert-True ($m.EndsWith($face + [char]0x2026)) 'cut after a whole pair'
    $short = (ConvertTo-PathwardenResult (New-PathwardenResult ($face * 2000))).Result.message
    Assert-Equal 4000 $short.Length 'not cut at 2,000 characters'
}

Test 'as a program: UTF-8 in and out, progress lines and the exit code' {
    $script = Join-Path $dir 'hello.ps1'
    $module = Join-Path $PSScriptRoot 'PathwardenAction.psm1'
    Set-Content -Path $script -Encoding UTF8 -Value @"
`$ErrorActionPreference = 'Stop'
Import-Module '$module'
Invoke-PathwardenAction -Describe @(@{ id = 'hello'; label = 'Hello'; sends = 'Nothing.' }) -Handlers @{
    hello = { param(`$Request) Write-PathwardenProgress "Hello `$(`$Request.finding.title)"; New-PathwardenResult "Said hello to `$(`$Request.finding.title)." }
}
"@
    $shell = (Get-Process -Id $PID).Path
    $psi = New-Object Diagnostics.ProcessStartInfo($shell, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`"")
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.EnvironmentVariables['PATHWARDEN_ACTION_RESULT'] = $resultPath
    $psi.EnvironmentVariables['PATHWARDEN_ACTION_REQUEST'] = 'run'
    Remove-Item $resultPath -ErrorAction SilentlyContinue
    $p = [Diagnostics.Process]::Start($psi)
    $title = 'Jos' + [char]0xE9 + ' ' + [char]0x2192 + ' Tier Zero'
    $bytes = [Text.Encoding]::UTF8.GetBytes((New-Request @{ action = 'hello'; finding = @{ fingerprint = 'PW-1'; title = $title } }))
    $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $p.StandardInput.Close()
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    Assert-Equal 0 $p.ExitCode "exit code ($err)"
    Assert-Equal "Hello $title" $out.Trim() 'progress line'
    $answer = [IO.File]::ReadAllText($resultPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
    Assert-Equal "Said hello to $title." $answer.message 'message'
}

Remove-Item -Recurse -Force $dir
Write-Host "$($script:count - $script:failures) of $script:count passed."
if ($script:failures) { exit 1 }
