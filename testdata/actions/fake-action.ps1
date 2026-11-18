# A fake finding action for Pathwarden's tests. It lists its actions for
# describe and pretends to open a ticket for run, without contacting
# anything. fake-action.sh does the same elsewhere.
$ErrorActionPreference = 'Stop'
$text = [Console]::In.ReadToEnd()
$req = $text | ConvertFrom-Json
# The request as it came, for the test to read (out_env names the variable).
if ($env:PW_FAKE_ACTION_OUT) { [IO.File]::WriteAllText($env:PW_FAKE_ACTION_OUT, $text) }
function Answer([string]$json) { [IO.File]::WriteAllText($env:PATHWARDEN_ACTION_RESULT, $json) }
if ($env:PATHWARDEN_ACTION_REQUEST -eq 'describe') {
    Answer '{"schema":"pathwarden.action-describe.v1","actions":[{"id":"open","label":"Open a ticket","description":"Opens a ticket in the fake desk.","sends":"The finding''s title and the note.","inputs":[{"id":"note","label":"Note","type":"textarea"},{"id":"urgency","label":"Urgency","type":"choice","choices":["Low","Medium","High"],"default":"Medium"}],"once":true,"follow_ups":["status"]},{"id":"status","label":"Check status","for":"record","sends":"The ticket''s number."},{"id":"ping","label":"Ping the team","sends":"The finding''s ID.","applies_to":{"min_severity":"critical"}}]}'
    exit 0
}
[Console]::Out.WriteLine('Opening a ticket')
if ($req.inputs.note -eq 'fail') {
    [Console]::Error.WriteLine('HTTP 403 from the fake desk')
    Answer '{"schema":"pathwarden.action-result.v1","ok":false,"message":"The fake desk said no."}'
    exit 1
}
if ($req.dry_run) {
    Answer '{"schema":"pathwarden.action-result.v1","ok":true,"message":"Would open a ticket (dry run)."}'
    exit 0
}
[Console]::Out.WriteLine('Ticket created')
Answer '{"schema":"pathwarden.action-result.v1","ok":true,"message":"Opened FAKE0001.","links":[{"label":"Open in the fake desk","url":"https://desk.example.com/FAKE0001"}],"records":[{"id":"fake-1","kind":"ticket","number":"FAKE0001","status":"Open","open":true,"url":"https://desk.example.com/FAKE0001","fields":{"Queue":"Identity"}}]}'
