# post-to-webhook.ps1: alert a team in chat

A finding action that posts a finding to a chat channel's incoming
webhook: Microsoft Teams, Slack, or anything that takes JSON. It returns a
message and keeps no record, so every click posts again, and each post is
listed in the finding's Activity.

It offers one action, **Alert the team** (`alert`), with one input,
**Note for the team**. It sends the finding's ID, title, severity and
summary, and the note.

## Settings

| Setting | Meaning |
|---|---|
| `webhook_env` | Required. The environment variable that holds the webhook's URL. The URL is a secret: anyone who has it can post. |
| `format` | `teams` (an Adaptive Card, for a Teams workflow's "When a Teams webhook request is received"), `slack` (`{"text": ...}`, also for Google Chat, Mattermost and Rocket.Chat), or `json` (the finding's ID, rule, title, status and text). Default: `json`. |

## Set it up

1. Copy `post-to-webhook.ps1` and `PathwardenAction.psm1` to
   `C:\Pathwarden\actions`.
2. Put the webhook's URL in a variable for your account, then open a new
   terminal and restart the app:

   ```powershell
   [Environment]::SetEnvironmentVariable('PATHWARDEN_ALERT_WEBHOOK', 'https://example.webhook.office.com/...', 'User')
   ```

3. Check it:

   ```powershell
   pathwarden action check C:\Pathwarden\actions\post-to-webhook.ps1 --setting webhook_env=PATHWARDEN_ALERT_WEBHOOK --setting format=teams
   ```

4. Add it, here for high and critical findings only:

   ```powershell
   pathwarden action add --name alert --min-severity high --setting webhook_env=PATHWARDEN_ALERT_WEBHOOK --setting format=teams -- powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\Pathwarden\actions\post-to-webhook.ps1
   pathwarden action test alert
   ```

   ```toml
   [[action]]
   name = "alert"
   command = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "C:\\Pathwarden\\actions\\post-to-webhook.ps1"]
   min_severity = "high"
   webhook_env = "PATHWARDEN_ALERT_WEBHOOK"
   format = "teams"
   ```

A dry run builds the post and checks the settings, and posts nothing.

## Try it without a chat service

Run [stub-desk.py](stub-desk.py), which takes any post to
`/api/hooks/NAME`, and point the variable at it:

```powershell
python stub-desk.py
$env:PATHWARDEN_ALERT_WEBHOOK = 'http://127.0.0.1:8765/api/hooks/team'
```

The helper allows `http://` only to this computer.

More: [Writing an action](../../docs/actions.md#a-chat-alert).
