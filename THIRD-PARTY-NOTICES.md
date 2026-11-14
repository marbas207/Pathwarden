# Third-party notices

Pathwarden is licensed under Apache-2.0. It includes or links the following
third-party software under its own license.

## RustHound-CE

Pathwarden's built-in collector (`pathwarden collect`, Cargo feature
`builtin`, on by default) links the `rusthound-ce` crate, version 2.5.30,
as a library: <https://github.com/g0h4n/RustHound-CE>,
<https://crates.io/crates/rusthound-ce>. It is vendored in
`vendor/rusthound-ce` (its LICENSE kept there) with newer zip, quick-xml and
DNS resolver dependencies; `vendor/rusthound-ce/Cargo.toml` lists every
change. Two private functions of its
`transport::ldap` module (the directory read loop and ranged-attribute
retrieval) are adapted in `crates/pathwarden-collect/src/builtin.rs` to report
progress.

```
MIT License

Copyright (c) 2024 Quentin Texier

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## BloodHound Query Library

Pathwarden's prepared queries (the app's Explore page, `pathwarden query
--prepared`) are the Active Directory queries of the BloodHound Query
Library, release `queries-2026-08-20`, built in as a pinned copy in
`crates/pathwarden-core/queries/`:
<https://github.com/SpecterOps/BloodHoundQueryLibrary>. Each query's
authors are credited as the library credits them.

```
MIT License

Copyright (c) 2025 SpecterOps

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Cytoscape.js

The local web UI's graph explorer (`pathwarden ui`, Explore) bundles
Cytoscape.js 3.34.3, unmodified, as
`crates/pathwarden-ui/src/assets/vendor/cytoscape.min.js` (435,503 bytes):
<https://js.cytoscape.org>, <https://github.com/cytoscape/cytoscape.js>.

- Source: `package/dist/cytoscape.min.js` from the npm registry tarball
  <https://registry.npmjs.org/cytoscape/-/cytoscape-3.34.3.tgz>
- Tarball integrity (as published by npm):
  `sha512-yfYGhRcGAntq6YBD583j4n0Eg3jIxvWmZtz/5uz9UYkeIStSlMxuUja+ec5j3iBD8nv1rwaOAYMW09tBdkSeaQ==`
- SHA-256 of the bundled file:
  `5f3b5b529546d5af1fc5628590af033b74511a5b6f789f5f4682845863228b91`

```
Copyright (c) 2016-2026, The Cytoscape Consortium.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## ldap3 (modified)

`vendor/ldap3` is ldap3 0.12.1 by Ivan Nejgebauer
(<https://github.com/inejge/ldap3>), under MIT or Apache-2.0 (its
`LICENSE-MIT` and `LICENSE-APACHE` are kept there), and built in place of
the crates.io release. It is copied from the `pathwarden` branch of
<https://github.com/marbas207/ldap3>. Changed: the SASL (GSSAPI sealing)
decoder in `src/protocol.rs`, which lost messages when a sealed buffer held
more than one of them (submitted upstream as inejge/ldap3#160); added
`Ldap::sasl_bind`, a public SASL bind step by Vincent Vanackere
(inejge/ldap3#159). The examples and dev-dependencies are left out.

## smb2-client (modified)

`vendor/smb2-client` is smb2-client 0.2.5 by icedracon
(<https://github.com/icedracon/smb2-client>), the SMB client of RustHound-CE
and dcerpc, under MIT (its `LICENSE` is kept there), and built in place of
the crates.io release. Changed: the client can require signing, asking the
server to sign and refusing any reply after sign-in whose signature is
missing or wrong (`src/lib.rs`, `src/client.rs`, `src/header.rs`, each change
marked "Pathwarden patch"). Off unless a caller turns it on.

## Other dependencies

Every release archive also holds `THIRD-PARTY-LICENSES.md`: the license text
of every Rust crate built into each of its executables, with the crates that
use it, generated from `Cargo.lock` by cargo-about when the archive is made
(`scripts/package.*`; settings in `about.toml`, template `about.hbs`). The
archive's `sbom/` folder lists the same crates as CycloneDX SBOMs.

Those crates (ldap3, tokio, rustls, ring, zip, serde and others) are under
MIT, Apache-2.0, BSD, ISC, Zlib or Unicode style licenses, with these
exceptions, both pulled in by RustHound-CE:

- `colored` 2.x: MPL-2.0. It is used unmodified; its source is at
  <https://github.com/colored-rs/colored> and on crates.io.
- `webpki-roots`: CDLA-Permissive-2.0 (Mozilla's root certificate list, used by
  RustHound-CE's HTTP client for its AD CS web-enrollment probe).

The Windows full build's desktop window (Cargo feature `desktop`) adds
`wry`, `tao`, `rfd` and `webview2-com` (MIT or Apache-2.0). Through
`webview2-com-sys` it statically links Microsoft's WebView2 loader
(`WebView2LoaderStatic.lib` from the Microsoft.Web.WebView2 SDK), under the
SDK's own license: <https://www.nuget.org/packages/Microsoft.Web.WebView2>.
The WebView2 Runtime itself is not shipped; it is part of Windows or
installed separately.

Test data, not shipped in any build: `testdata/sarif/sarif-schema-2.1.0.json`
is the OASIS SARIF 2.1.0 schema, with OASIS's copyright notice in
`testdata/sarif/README.md`.

To list them from the source: `cargo tree -e normal`; `cargo deny check
licenses` checks every license against the list in `deny.toml`.
