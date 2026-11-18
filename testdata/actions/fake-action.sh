#!/bin/sh
# A fake finding action for Pathwarden's tests. It lists its actions for
# describe and pretends to open a ticket for run, without contacting
# anything. fake-action.ps1 does the same on Windows.
req=$(cat)
# The request as it came, for the test to read (out_env names the variable).
if [ -n "$PW_FAKE_ACTION_OUT" ]; then printf '%s' "$req" > "$PW_FAKE_ACTION_OUT"; fi
answer() { printf '%s' "$1" > "$PATHWARDEN_ACTION_RESULT"; }
if [ "$PATHWARDEN_ACTION_REQUEST" = describe ]; then
    answer '{"schema":"pathwarden.action-describe.v1","actions":[{"id":"open","label":"Open a ticket","description":"Opens a ticket in the fake desk.","sends":"The finding'"'"'s title and the note.","inputs":[{"id":"note","label":"Note","type":"textarea"},{"id":"urgency","label":"Urgency","type":"choice","choices":["Low","Medium","High"],"default":"Medium"}],"once":true,"follow_ups":["status","close"]},{"id":"status","label":"Check status","for":"record","sends":"The ticket'"'"'s number."},{"id":"ping","label":"Ping the team","sends":"The finding'"'"'s ID.","applies_to":{"min_severity":"critical"}},{"id":"close","label":"Close the ticket","for":"record","when":["fixed"],"sends":"The ticket'"'"'s number."}]}'
    exit 0
fi
case "$req" in
*'"action":"status"'*)
    # A follow-up: the ticket it runs on is closed now.
    answer '{"schema":"pathwarden.action-result.v1","ok":true,"message":"FAKE0001 is Closed.","records":[{"id":"fake-1","kind":"ticket","number":"FAKE0001","status":"Closed","open":false}]}'
    exit 0 ;;
esac
echo 'Opening a ticket'
case "$req" in
*'"note":"slow"'*)
    # Waits, with a process of its own, until it is stopped.
    (sleep 8; [ -n "$PW_FAKE_ACTION_MARK" ] && touch "$PW_FAKE_ACTION_MARK") &
    echo 'Waiting for the fake desk'
    sleep 120 ;;
esac
case "$req" in
*'"note":"fail"'*)
    echo 'HTTP 403 from the fake desk' >&2
    answer '{"schema":"pathwarden.action-result.v1","ok":false,"message":"The fake desk said no."}'
    exit 1 ;;
esac
case "$req" in
*'"dry_run":true'*)
    answer '{"schema":"pathwarden.action-result.v1","ok":true,"message":"Would open a ticket (dry run)."}'
    exit 0 ;;
esac
echo 'Ticket created'
answer '{"schema":"pathwarden.action-result.v1","ok":true,"message":"Opened FAKE0001.","links":[{"label":"Open in the fake desk","url":"https://desk.example.com/FAKE0001"}],"records":[{"id":"fake-1","kind":"ticket","number":"FAKE0001","status":"Open","open":true,"url":"https://desk.example.com/FAKE0001","fields":{"Queue":"Identity"}}]}'
