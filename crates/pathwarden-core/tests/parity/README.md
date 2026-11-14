# Cypher parity goldens

Golden-snapshot structure for proving **1:1 result parity** between Pathwarden's
Cypher engine and BloodHound CE (BHE).

The Pathwarden side runs in ordinary CI: `crates/pathwarden-core/tests/cypher_parity.rs`
loads the shared capture, runs each query through the engine, normalises, and
asserts equality against the committed golden files here. **No BHE is needed at
test time.**

Without goldens or without `data/goad` (git-ignored, so absent in CI) the test
skips, and says so: a `SKIPPED cypher parity: ...` line in the test output
(printed past the harness's capture), a `::warning` annotation on GitHub
Actions, and a failure instead of a skip under `PATHWARDEN_REQUIRE_PARITY=1`
(or `true`; set it wherever the capture and goldens are expected).

## What is captured where

- `queries.json` — the query set `Q` (the spike's six shapes; the full Q1–Q16
  from design §4.3 drop in as the parser grows). Committed, human-readable.
- `golden/<query-id>.json` — one golden per query: the normalised result BHE
  returned on the shared capture, plus a header recording the pinned BHE build.
  **These do not exist yet** — see "Capturing goldens" below. `golden/` holds
  only a `.gitkeep` until a capture run drops real files in.

## The normalisation contract (design §4.1)

- A node ⇒ its `objectid`, upper-cased. Compare **sets** of objectids.
- A relationship ⇒ the triple `(source_objectid, TYPE, target_objectid)`.
- Drop BHE's `Base` superlabel and internal graph ids before comparing.
- Map `Tag_Tier_Zero` ⇄ Pathwarden's tier-zero flag.
- Order-insensitive unless the query has `ORDER BY`.

## Golden file schema

```json
{
  "id": "Q1",
  "query": "MATCH (n:Domain) RETURN n",
  "bhe_version": "bloodhound-ce@sha256:<digest>",
  "captured_at": "2026-10-18T00:00:00Z",
  "capture": "data/goad (SharpHound 2.3.3, SEVENKINGDOMS/NORTH/ESSOS)",
  "nodes": ["S-1-5-21-...-1000", "S-1-5-21-...-1001"],
  "relationships": [["S-1-5-21-...-1101", "MemberOf", "S-1-5-21-...-512"]]
}
```

`nodes` is the id-set of the RETURN projection; `relationships` is the set of
matched edge triples. The test compares both as sets.

## Capturing goldens (NOT done here; needs a BHE instance — separate step)

Standing BHE up is a one-time/on-demand lab job, deliberately **off the CI
path** (it needs Postgres + the API in Docker). This spike does **not** stand it
up. When ready:

1. Bring up a pinned BHE via docker-compose; record the image digest.
2. Ingest the *same* `data/goad` SharpHound JSON BHE eats (identical input to
   Pathwarden).
3. For each query in `queries.json`, call `POST /api/v2/graphs/cypher` with
   `{"query": "<cypher>", "include_properties": true}` (JWT bearer from
   `POST /api/v2/login`; verify with `GET /api/v2/self`). Confirm the exact
   route against the running instance's API Explorer.
4. Normalise each response to the schema above and write
   `golden/<id>.json` with the BHE digest in the header.
5. Commit the goldens. Re-capture only when `queries.json`, the capture, or the
   pinned BHE version changes.

A `harness/capture_bhe.py` script (design §4.2) will automate steps 1–4; it is
not part of this spike.

## Early parity questions to resolve at first capture (design §5.2, §6.1)

- **Tier Zero set** (`Tag_Tier_Zero`): Pathwarden adds its own tier-zero reasons
  and zones, so our Tier Zero set may differ from BHE's on this capture. The
  parity claim is "same engine semantics over the same tier-zero set", not
  "identical tiering policy".
- **ADCS edges** (`ADCSESC1`, ...): derived in post-processing on both sides;
  confirm they are computed identically or scope them out with a note (Gap 4).
- **Placeholders**: Pathwarden materialises referenced-but-uncollected objects
  as placeholder nodes; decide at capture whether BHE's stub nodes line up.
