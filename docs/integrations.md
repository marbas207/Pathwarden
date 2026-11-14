# Integrations: SARIF, DefectDojo, Jira and PingCastle

| Integration | Direction | How | Tested against |
|---|---|---|---|
| [SARIF 2.1.0](#sarif-210) | Out | `pathwarden export sarif` | The OASIS JSON schema. |
| [DefectDojo](#defectdojo) | Out | `pathwarden export defectdojo` | The parser's rules; not yet a live DefectDojo. |
| [Jira](#jira) | Out | The `pathwarden-output-jira` plugin | A live Jira Cloud test site and a fake Jira Cloud; not yet Data Center. |
| [ServiceNow](../crates/pathwarden-output-servicenow/README.md) | Out | The `pathwarden-output-servicenow` plugin | A live ServiceNow developer instance (incidents). |
| [PingCastle](#pingcastle) | In | Its `ad_hc_<domain>.xml` with `-i` | Hand-written files; not yet a real report. |

Each one keys on the finding ID, so the other system can match a finding
across runs, close it when it is fixed and reopen it when it comes back.

## Exports

```sh
pathwarden export sarif      --event event.json -o pathwarden.sarif
pathwarden export defectdojo --event event.json -o pathwarden-dd.json
```

`--event` reads the event document `pathwarden run --event` writes, so each
finding carries its change since the last run. `--run RUN` exports a run of
the app, as its run page's **Download** › **Findings file…** does, and `-i`
analyzes collector data on the spot. Accepted risks are included and marked.
Findings the run couldn't check ("can't tell") are left out, with a warning.

### SARIF 2.1.0

The finding ID is in `partialFingerprints["pathwardenFingerprint/v1"]`,
accepted risks carry a `suppressions` entry, and objects are logical
locations. GitHub code scanning is not a target: it needs a file in the
repository for each result.

### DefectDojo

The export is DefectDojo's **Generic Findings Import** JSON, with the
finding ID in `unique_id_from_tool` and `"type": "Pathwarden"`. Object names
in it are escaped for Markdown, which DefectDojo shows, so they appear as
written.

Some titles carry counts, so set DefectDojo to deduplicate Pathwarden
findings on the finding ID once, in the DefectDojo server's environment, and
restart it:

```sh
DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Pathwarden": "unique_id_from_tool"}'
```

Then reimport into the same test every run. Findings still there stay, new
ones are added, missing ones are closed, and ones that come back are
reactivated:

```sh
curl -sf -X POST "https://defectdojo.example.com/api/v2/reimport-scan/" \
  -H "Authorization: Token $DD_API_TOKEN" \
  -F "scan_type=Generic Findings Import" \
  -F "product_name=Active Directory" -F "engagement_name=Pathwarden" \
  -F "test_title=Pathwarden SCALE" -F "auto_create_context=true" \
  -F "close_old_findings=true" -F "file=@pathwarden-dd.json"
```

When a run couldn't check everything, `export` warns. Skip that run's
reimport, or pass `close_old_findings=false`, so its unchecked findings
aren't closed.

## Jira

The Jira plugin creates an issue for each new finding, comments when one
comes back, reopens issues closed while the finding is still there, and
closes issues whose finding is fixed. It works with Jira Cloud and Data
Center. Set it up in the app (**Ticketing and alerts** > **Add Jira**), with
`pathwarden plugins add jira`, or in `pathwarden.toml`; every setting is in
its [README](../crates/pathwarden-output-jira/README.md). Start with **Test**
(a dry run) on a test project.

```toml
[[output]]
plugin = "jira"
instance = "https://example.atlassian.net"
project = "SEC"
```

## PingCastle

Give a PingCastle health check report to Pathwarden with the collection, and
each risk rule it triggers becomes a hygiene finding, tracked from run to
run like any other:

```sh
pathwarden run -i .\collect -i .\ad_hc_scale.local.xml --state .\state
```

- Pathwarden reads an `.xml` file given with `-i`, or `ad_hc_*.xml` files in
  a folder; not files inside a `.zip`.
- Rule IDs are `PC-<RiskId>`, such as `PC-A-MinPwdLen`. There is one finding
  per rule and domain.
- Severity comes from PingCastle's points: 0 Info, 1 to 5 Low, 6 to 10
  Medium, 11 to 15 High, above 15 Critical.
- To retest, run PingCastle again and give Pathwarden the new report. A run
  without a report for that domain holds its PingCastle findings as can't
  tell.
- The report isn't signed or checked against the directory, and its
  findings are marked as imported. Keep it with the collector output.
