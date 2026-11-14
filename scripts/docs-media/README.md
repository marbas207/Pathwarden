# Docs media

The screenshots and GIFs in `docs/images/` are generated from the real program
running on the demo data, so they can be redone whenever the UI or the CLI
changes. You need Node 22+, Chrome, Python with Pillow, and a release build
(`cargo build --release`).

**CLI screenshots** (`cli-*.png`): run each command with colors on and render
it in a terminal window.

```sh
python scripts/docs-media/cli_shots.py
```

**GIFs**: `record.mjs` drives headless Chrome through a scenario (a JSON list
of steps: wait, click, hover, scroll, eval). It draws a cursor that glides to
each element before clicking, and saves every frame Chrome paints.
`make_gif.py` merges repeated frames and writes a small looping GIF.

```sh
pathwarden demo -o target/docs-media/demo-report.html  # the demo, with its made-up history
node scripts/docs-media/record.mjs scenario.json target/docs-media/frames
python scripts/docs-media/make_gif.py target/docs-media/frames docs/images/report-tour.gif
```

A scenario:

```json
{
  "url": "file:///C:/Pathwarden/target/docs-media/demo-report.html",
  "width": 1280, "height": 800,
  "steps": [
    {"do": "wait", "ms": 2200},
    {"do": "click", "sel": "#tab-findings", "ms": 1200},
    {"do": "click", "sel": "details.group[data-rule=\"PW-004\"] > summary", "ms": 900},
    {"do": "scroll", "sel": "svg.pathviz", "block": "center", "ms": 2600}
  ]
}
```

For the web UI, start a throwaway instance (`pathwarden ui --no-browser
--workspace <temp dir> --port <port>`) and pass the link it prints as the
third argument (it replaces the scenario's `url`). The link works once, so
restart the instance for each recording, on a fresh copy of its workspace.

Pages show paths and names from the computer they run on, so give the
instance neutral ones. On Windows, map a scratch folder to a drive letter
(`subst P: <scratch folder>`), copy `pathwarden.exe` and
`pathwarden-output-servicenow.exe` to `P:\Program Files\Pathwarden`, and start
it from there with `--workspace P:\Pathwarden` and these variables set for the
process: `LOCALAPPDATA`, `APPDATA`, `TEMP` and `TMP` in `P:\`,
`USERDNSDOMAIN=SCALE.LOCAL`, `USERDOMAIN=SCALE`, `USERNAME=analyst`,
`COMPUTERNAME=WS-ANALYST01` and `LOGONSERVER=\\DC01` (the Collect wizard
fills in the demo's domain from them). "A workspace with the demo run" is one
where **Try the demo** has finished once; copy it for each recording, since
several scenarios change settings.

The scenarios behind the GIFs in `docs/images/` are in `scenarios/`, recorded
at 1440×900 and scaled to 960 wide. All of them start from the UI:

| GIF | Scenario | Start from |
| --- | --- | --- |
| `ui-demo.gif` (also Try the demo) | `ui-demo.json` | an empty workspace |
| `analyze-a-collection.gif` | `analyze-a-collection.json` | an empty workspace |
| `collect-from-ad.gif` | `collect-from-ad.json` | an empty workspace (stops before Check, which contacts the domain controller) |
| `opengraph-sources.gif` | `opengraph-sources.json` | an empty workspace (uploads `fixtures/taskhound_opengraph.json`, a made-up TaskHound file for the demo) |
| `explorer.gif`, `explore-a-path.gif` | `explorer.json`, `explore-a-path.json` | a workspace with the demo run |
| `report-tour.gif`, `report-remediation.gif` | `report-tour.json`, `report-remediation.json` | a workspace with the demo run |
| `read-the-report.gif`, `follow-the-remediation-path.gif`, `accept-a-risk.gif` | the scenario of the same name | a workspace with the demo run |
| `rule-severity.gif`, `environments.gif`, `privilege-zone.gif` | the scenario of the same name | a workspace with the demo run |
| `schedule-nightly-runs.gif`, `set-up-ticketing.gif`, `history-storage.gif` | the scenario of the same name | a workspace with the demo run (no task is created, no plugin is tested, the history goes to a folder) |
| `evidence-pack.gif`, `export-findings.gif` | the scenario of the same name | a workspace with the demo run (`evidence-pack` creates the signing key, so the workspace must have none yet) |

```sh
node scripts/docs-media/record.mjs scripts/docs-media/scenarios/ui-demo.json target/docs-media/f-demo "<one-time link>"
python scripts/docs-media/make_gif.py target/docs-media/f-demo docs/images/ui-demo.gif --scenario scripts/docs-media/scenarios/ui-demo.json
```

`--scenario` applies the scenario's `gif` options: how long the last frame is
held, and `--fast FROM-TO:FACTOR` for a stretch to play faster (the wait for
an analysis). The times depend on the computer, so check them after
recording again. Each scenario's `settle` lets the rail's Crown W finish
drawing itself in before recording starts. Recording emulates a dark color
scheme.

Only record synthetic data such as the demo: never a real collection.
