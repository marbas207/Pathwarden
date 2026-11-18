# A Pathwarden finding action: post a finding to a chat channel's incoming
# webhook (Microsoft Teams, Slack, or anything that takes JSON). It returns
# a message; it keeps no record. See post-to-webhook.md beside it.
#
# [[action]]
# name = "alert"
# command = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
#            "-File", "C:\\Pathwarden\\actions\\post-to-webhook.ps1"]
# webhook_env = "PATHWARDEN_ALERT_WEBHOOK"   # the variable that holds the webhook's URL
# format = "teams"                           # teams, slack or json (default: json)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PathwardenAction.psm1')

$actions = @(
    @{
        id          = 'alert'
        label       = 'Alert the team'
        description = 'Posts the finding to the team''s chat channel.'
        sends       = 'The finding''s ID, title, severity and summary, and your note, to the chat channel''s webhook.'
        inputs      = @(
            @{ id = 'note'; label = 'Note for the team'; type = 'textarea'; max = 1000 }
        )
    }
)

# The finding as a few lines of text.
function Get-Summary($Request) {
    $f = $Request.finding
    $severity = if ($f.PSObject.Properties['severity'] -and $f.severity) { $f.severity } else { $f.status }
    $lines = @("$($f.fingerprint) ($severity): $($f.title)")
    if ($f.PSObject.Properties['summary'] -and $f.summary) { $lines += $f.summary }
    if ($Request.inputs.note) { $lines += "Note from $($Request.requested_by.by): $($Request.inputs.note)" }
    $lines
}

# The body each kind of webhook takes.
function Get-Body($Request, [string]$Format) {
    $lines = Get-Summary $Request
    switch ($Format) {
        'slack' { @{ text = ($lines -join "`n") } }
        'teams' {
            # A Teams workflow's "When a Teams webhook request is received"
            # takes an Adaptive Card.
            $blocks = @(@{ type = 'TextBlock'; text = $lines[0]; weight = 'Bolder'; wrap = $true })
            $blocks += @($lines | Select-Object -Skip 1 | ForEach-Object { @{ type = 'TextBlock'; text = $_; wrap = $true } })
            @{
                type        = 'message'
                attachments = @(@{
                    contentType = 'application/vnd.microsoft.card.adaptive'
                    content     = @{
                        '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                        type      = 'AdaptiveCard'; version = '1.4'; body = $blocks
                    }
                })
            }
        }
        default {
            $f = $Request.finding
            @{ fingerprint = $f.fingerprint; rule = $f.rule; title = $f.title; status = $f.status
               text = ($lines -join "`n"); requested_by = $Request.requested_by.by }
        }
    }
}

Invoke-PathwardenAction -Describe $actions -Handlers @{
    alert = {
        param($Request)
        $url = Get-PathwardenSecret -Request $Request -Name webhook
        $format = Get-PathwardenSetting -Request $Request -Name format -Default 'json'
        if ($format -notin 'teams', 'slack', 'json') { throw "format must be teams, slack or json, not '$format'." }
        $body = Get-Body $Request $format
        if ($Request.dry_run) {
            # Everything but the post: the settings and the body are checked.
            return New-PathwardenResult "Dry run: would post $($Request.finding.fingerprint) to the $format webhook."
        }
        Write-PathwardenProgress 'Posting to the webhook'
        $null = Invoke-PathwardenHttp -Request $Request -Method Post -Uri $url -Body $body
        New-PathwardenResult "Posted $($Request.finding.fingerprint) to the team's channel."
    }
}
