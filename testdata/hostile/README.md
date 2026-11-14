# Hostile names

`testdata/forest` with its names made awkward for anything that is meant to
leave them out: a domain with a non-ASCII letter (`KESTRELÜBER.LOCAL`), an
account with quotes and markup in its name (`ALICE "<IMG SRC=X>" NOVÁK`), a
host with a ligature (`SRV-ÆTHER01`) and a group whose name starts like a
placeholder (`DOMAIN-1 ZØNE admins`). Made up; the structure and SIDs are the
forest fixture's.

The diagnostics bundle tests (`crates/pathwarden-ui/tests/diagnose.rs`,
`crates/pathwarden-cli/tests/diagnose.rs`) check that none of these names,
their parts or their JSON-escaped forms reach a bundle.
