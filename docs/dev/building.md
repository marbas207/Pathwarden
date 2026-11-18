# Building Pathwarden from source

Pathwarden is written in Rust and builds into a single executable. Expect
15–30 minutes the first time, mostly installing tools and the first compile.

## The two variants

| | Full | Lean |
|---|---|---|
| Analysis, reports, `pathwarden run`, plugins, `pathwarden ui` | yes | yes |
| Built-in collector (`pathwarden collect` with no other tool) | yes, RustHound-CE inside | no: drives an installed SharpHound or RustHound-CE |
| Size (Windows) | about 16 MB | about 6 MB |
| First build | about 4 minutes | about 1.5 minutes |

Build **full** for a workstation that collects and analyzes. Build **lean**
for a server or pipeline that already gets SharpHound output.

## 1. Install the tools

You need Rust 1.89 or newer (in this repository rustup installs the exact
release `rust-toolchain.toml` names, with rustfmt and clippy, on the first
build), a C compiler (a few dependencies contain C code) and Git.

**Windows:**

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install Rustlang.Rustup
winget install Git.Git
```

The Build Tools give the linker and C compiler ("Desktop development with
C++"); skip them if Visual Studio already has that workload. Open a new
terminal so the PATH changes apply, then check `rustc --version`.

**Linux:**

```sh
sudo apt install build-essential git curl      # Debian / Ubuntu
sudo dnf install gcc make git curl             # RHEL / Fedora / Rocky
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

No OpenSSL, Kerberos or other system libraries are needed: TLS and the
directory protocols are implemented in Rust. CI checks formatting, cargo deny
and clippy on Linux on every push; most hands-on testing has been on Windows.

## 2. Get the source and build

```sh
git clone https://github.com/marbas207/Pathwarden
cd Pathwarden
cargo build --release                                # full
cargo build --release -p pathwarden --no-default-features --target-dir target/lean   # lean
cargo build --release -p pathwarden-output-servicenow -p pathwarden-output-jira --target-dir target/lean
cargo build --release -p pathwarden --features desktop   # full with the desktop window (Windows)
```

The repository is private for now: sign in with your GitHub account or
`gh auth login`. The desktop window build is what the Windows full release
archive ships ([The desktop window](../ui.md#the-desktop-window)); it adds
about 0.7 MB.

The executables land in `target/release/` (full) or `target/lean/release/`
(lean): `pathwarden`, `pathwarden-output-servicenow` and
`pathwarden-output-jira` (`.exe` on Windows). There is no installer: copy
them wherever you like, with the two plugins next to `pathwarden` or in a
`plugins` folder beside it. Pathwarden only looks for plugins there.

Check it works:

```sh
target/release/pathwarden --version
target/release/pathwarden report -i demo -o demo-report.html
```

To update: `git pull`, `rustup update stable`, `cargo build --release`.

## Before every merge

CI runs only the formatting, cargo-deny and clippy checks on push. Run these
locally:

```sh
cargo fmt --all
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo deny --locked check                               # deny.toml; cargo install cargo-deny --locked
cargo test --locked --workspace
cargo test --locked -p pathwarden -p pathwarden-ui --no-default-features   # lean
PATHWARDEN_TIMINGS=1 target/release/pathwarden report -i demo -o r.html   # per-phase timings
```

The crates: `pathwarden-core` (analysis), `pathwarden-cli` (the `pathwarden`
binary), `pathwarden-ui` (the app), `pathwarden-collect` (collection),
`pathwarden-output-servicenow` and `pathwarden-output-jira` (plugins), and
`pathwarden-export` (SARIF and DefectDojo). `scripts/` has the generators for
the test fixtures and the synthetic demo forest.

### Checking the Linux build from Windows

Code behind `#[cfg(windows)]` leaves imports unused on Linux, which CI's Linux
clippy rejects. To catch that before pushing:

```powershell
rustup target add x86_64-unknown-linux-gnu
pip install ziglang
powershell -NoProfile -File scripts\linux-check.ps1 -TargetDir D:\pw-build\linuxcheck
```

It runs the full and lean clippy as CI does (`-Full` or `-Lean` for one). It
uses [zig](https://ziglang.org) as the Linux C compiler for ring and mimalloc
(from `pip install ziglang`, `zig` on `PATH`, or `-Zig C:\path\to\zig.exe`),
through wrappers in `<target dir>\zig-wrappers`, and needs Python. Nothing is
linked, so it checks lints and compile errors only. Use a separate target
directory with a few GB free.

### Dependency advisories

`cargo deny check` ([`deny.toml`](../../deny.toml), cargo-deny 0.20) fails on
any vulnerable, unmaintained, unsound or yanked crate, any license outside its
list, and any source other than crates.io, except the advisories listed there,
each with its reason. As of 2026-11-13: rsa and crypto-bigint through picky
and age (Kerberos certificate auth and age's p256 recipients are unused; no
release of either takes the fixed versions), bincode and number_prefix
through rusthound-ce, rustls-pemfile and basic-toml (unmaintained, no
security impact), and glib and proc-macro-error in wry's Linux GTK backend
(no release builds the desktop window for Linux). Recheck the list on every
dependency bump; cargo-deny reports an entry that no longer matches, so drop
it then. `cargo audit` reads [`.cargo/audit.toml`](../../.cargo/audit.toml),
which ignores only the three of these that it counts as failures (rsa,
crypto-bigint, glib). It checks every platform, so it also warns about
pin-utils (unmaintained), which sspi links on macOS only.

rusthound-ce is vendored (`vendor/rusthound-ce`, through `[patch.crates-io]`)
with zip 9, quick-xml 0.41 and hickory-resolver 0.26 in place of its zip 4,
quick-xml 0.37 and trust-dns-resolver 0.23; its header lists every change.
Drop the copy once an upstream release has them.

Most come through `rusthound-ce`, so the lean build has fewer. rusthound-ce is
pinned (`=2.5.30`); its newer single-author dependencies (smb2-client, dcerpc,
ms-pac-forge, windows-sddl) parse SMB responses with `--scope all`, so diff
them (for example with `cargo vet`) whenever the pin moves.

## Packaging

```powershell
powershell -NoProfile -File scripts\package.ps1     # Windows
```

```sh
sh scripts/package.sh                              # Linux
sh scripts/package.sh --target x86_64-unknown-linux-musl   # static linux-x64-musl
```

Both need `cargo install cargo-about --locked --features cli` (license texts)
and `cargo install cargo-cyclonedx --locked` (SBOMs). The musl build also
needs `rustup target add x86_64-unknown-linux-musl` and `musl-tools`.

Archives land in `dist/`, for example
`pathwarden-1.0.0-rc.2-windows-x64-full.zip` and
`pathwarden-1.0.0-rc.2-windows-x64-lean.zip`. Each holds the three executables,
`LICENSE`, `THIRD-PARTY-NOTICES.md`, `THIRD-PARTY-LICENSES.md` (every crate's
license, from cargo-about), `sbom/` (a CycloneDX 1.5 SBOM per executable, from
cargo-cyclonedx), the README, the example configuration and the collector
scripts. Beside each archive goes `pathwarden`'s SBOM (`<archive>.cdx.json`),
and `dist/SHA256SUMS.txt` is written fresh with exactly this run's archives
and SBOMs.

The scripts build with `--locked` on the pinned toolchain and refuse a
working tree with uncommitted changes, so an archive always matches a commit
(`-Force` / `--force` for a local test build; `-OutDir` / `--out-dir` for
another folder). On Windows each variant builds in its own folder
(`target\full`, `target\lean`) so another build can't replace the executable
being packaged. The script checks each staged `pathwarden.exe` (the version,
and `--window` in `ui --help` for the full build), writes the zip with .NET's
`ZipFile` and forward slashes, then reads it back and stops if any entry name
has a backslash or the entries differ from the staged files. (`unzip -l
<zip>`, or `tar -tf <zip>` on Windows, lists them.)

## Release builds

The Windows zips are built and signed on a Windows workstation. The Linux
archives come from the release workflow, started by hand from the release
tag with **Build only the Linux archives** (`linux_only`), and are added to
the release with a fresh `SHA256SUMS.txt` before the sums are signed.

- **CI.** [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) runs
  `cargo fmt --check`, `cargo deny check` and clippy (full and lean, warnings
  as errors) on Linux for every push to `main` and every pull request. The
  Linux and Windows test suites run only on demand (Actions > CI > Run
  workflow, or `gh workflow run CI --ref <branch>`), normally once before a
  release. Every command uses `--locked`.
- **Pinned toolchain.** [`rust-toolchain.toml`](../../rust-toolchain.toml)
  names the exact Rust release for every build. To move to a newer Rust,
  change `channel` in a commit of its own and run the full checks.
  `rust-version` in `Cargo.toml` is the oldest Rust that builds Pathwarden.
- **Prepared queries.** Before a release, run
  `powershell -NoProfile -File scripts\update-queries.ps1` (the latest
  `queries-*` release of the BloodHound Query Library, or
  `-Tag queries-YYYY-MM-DD`). It checks the download against GitHub's digest,
  rewrites `crates\pathwarden-core\queries\` (`Queries.json`, `LICENSE`,
  `SOURCE` with both checksums), updates THIRD-PARTY-NOTICES.md and
  docs/running.md, and prints the queries added, removed and changed. Then
  `cargo test -p pathwarden-ui --test prepared` lists the queries Pathwarden
  can't offer and the lines `unsupported.toml` needs
  (`PATHWARDEN_WRITE_PREPARED=1` writes them). Check `findings.toml` for new
  overlaps, and commit. Pathwarden never fetches the library at build or run
  time.
- **The desktop window.** On a Windows desktop with the WebView2 Runtime, run
  the no-port smoke test by hand. It opens the window hidden, runs the demo,
  opens the report, stops from Stop Pathwarden, and fails if `pathwarden.exe`
  ever listens on a TCP port. The window's guards are unit tests in
  `crates/pathwarden-desktop/src/guard.rs` and run with every test suite.

  ```powershell
  $env:PATHWARDEN_E2E_DESKTOP = "1"
  cargo test -p pathwarden --features desktop --test desktop_smoke -- --ignored --nocapture
  ```

- **A release.** Set the version in `Cargo.toml`, commit, tag
  (`git tag -a v0.2.0 -m "Pathwarden 0.2.0" && git push origin v0.2.0`), check
  the tag out, run `cargo deny check` and `scripts\package.ps1` (with
  `CARGO_BUILD_JOBS=2` to keep the machine usable). Create a draft release
  with
  `gh release create v0.2.0 --draft --notes-file <notes> dist\pathwarden-0.2.0-* dist\SHA256SUMS.txt`,
  then sign its sums with
  `gh workflow run "Sign release sums" --ref main -f tag=v0.2.0` (about a
  minute). Check the draft and publish it by hand.
- **Release workflow.**
  [`.github/workflows/release.yml`](../../.github/workflows/release.yml)
  (Actions > Release > Run workflow, on the tag) builds the Windows archives
  and the Linux ones (`x86_64-unknown-linux-gnu` on Ubuntu 22.04 for an old
  glibc; tick "musl" for static archives too), writes `SHA256SUMS.txt` over
  all of them, records build provenance for every archive and SBOM with
  `actions/attest-build-provenance`, and attaches it all to a draft release.
  The Linux job takes about 10 minutes. It runs only from a tag, and a re-run
  replaces the files of a draft only, never those of a published release.
- **Signed sums.** [`.github/workflows/sign-sums.yml`](../../.github/workflows/sign-sums.yml)
  ("Sign release sums", by hand, on `main`, with the tag; every release from
  1.0.0-rc.1) downloads the release, checks that `SHA256SUMS.txt` lists every
  file and that each matches, signs it keyless with cosign under the
  workflow's GitHub identity (no key to keep; Sigstore's public log records
  the repository name, not a person), and attaches
  `SHA256SUMS.txt.sigstore.json`. It refuses any ref but `main`, since the
  identity users check names `refs/heads/main`.

### Building the Linux archives locally (WSL)

On a Linux machine, or in WSL (`wsl --install -d Ubuntu-22.04` once, as an
administrator; 22.04 for an old glibc) with the Linux tools and the packaging
tools above. Clone **on the Linux file system**: building in `/mnt/c` is very
slow, and a Windows `target\` must not be shared.

```sh
git clone https://github.com/marbas207/Pathwarden ~/pathwarden && cd ~/pathwarden
git checkout v0.2.0
CARGO_BUILD_JOBS=4 sh scripts/package.sh
cp dist/* /mnt/c/path/to/release/linux/
```

That `dist/SHA256SUMS.txt` lists only the Linux files: before uploading,
write one over every asset of the release (`sha256sum -- *.zip *.tar.gz
*.cdx.json > SHA256SUMS.txt` in a folder holding all of them). Locally built
archives have no provenance.

### Code signing

`scripts\package.ps1` signs `pathwarden.exe` and both plugins in each
variant, after the build check and before zipping, with
[Azure Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/how-to-signing-integrations)
(formerly Trusted Signing), when these environment variables are set:

| Variable | Value |
|---|---|
| `PW_SIGN_ENDPOINT` | The account's regional endpoint, for example `https://weu.codesigning.azure.net` (a wrong region fails with 403) |
| `PW_SIGN_ACCOUNT` | The Artifact Signing account name |
| `PW_SIGN_PROFILE` | The certificate profile name |
| `PW_SIGN_DLIB` | Full path to the x64 `Azure.CodeSigning.Dlib.dll` |
| `PW_SIGNTOOL` | Optional: signtool.exe; by default the newest x64 one of the Windows SDK |

All four `PW_SIGN_*`, or none: with none, the script says the executables are
unsigned and carries on; with some, it stops. It signs with SHA-256 and
Microsoft's timestamp server
(`signtool sign /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 /dlib ... /dmdf ...`,
the metadata in a temporary file removed after), checks every signature with
`Get-AuthenticodeSignature` (`Valid`, or it stops), and reruns the build
check on the signed `pathwarden.exe`.

Once, on the release machine:

1. **signtool**: `winget install Microsoft.WindowsSDK.10.0.26100`, or
   "Windows SDK Signing Tools for Desktop Apps" in the Visual Studio
   Installer.
2. **The .NET 8 runtime** (`winget install Microsoft.DotNet.Runtime.8`), which
   the dlib needs.
3. **The dlib**: the `Microsoft.ArtifactSigning.Client` NuGet package
   (`nuget install Microsoft.ArtifactSigning.Client -OutputDirectory C:\tools\artifactsigning`,
   or unzip the `.nupkg`). Point `PW_SIGN_DLIB` at
   `bin\x64\Azure.CodeSigning.Dlib.dll` inside it.
4. **Sign in**: `az login` as an account with the "Artifact Signing
   Certificate Profile Signer" role (formerly "Trusted Signing Certificate
   Profile Signer") on the certificate profile.

In the release workflow: add a protected `release` environment, sign in to
Azure there with `azure/login` (OIDC, pinned by SHA), install the dlib, and
set `PW_SIGN_*` for the "Build and package" step. Never put credentials in
the repository.

## Verifying a download

1. **Checksum.** Download `SHA256SUMS.txt` from the same release and check
   the archive against it:

   ```sh
   sha256sum --check --ignore-missing SHA256SUMS.txt
   ```

   ```powershell
   (Get-FileHash .\pathwarden-0.2.0-windows-x64-full.zip -Algorithm SHA256).Hash.ToLower()
   # compare with the line for that file in SHA256SUMS.txt
   ```

2. **Provenance** (archives built by the release workflow). Each archive and
   SBOM has a signed build provenance attestation that names the
   repository, the workflow, the tag and the commit it was built from. Check
   it with the [GitHub CLI](https://cli.github.com):

   ```sh
   gh attestation verify pathwarden-0.2.0-linux-x64-full.tar.gz --repo marbas207/Pathwarden
   ```

   It succeeds only for a file built by this repository's release workflow.
   (Attestations need a public repository, so releases made while the
   repository is private have none; the workflow skips that step.)

3. **Signature over the sums.** `SHA256SUMS.txt.sigstore.json` beside it is
   a Sigstore signature of `SHA256SUMS.txt`, made by this repository's
   "Sign release sums" workflow on `main` after it checked every file of the
   release against the sums. Check it with
   [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
   (2.4 or later):

   ```sh
   cosign verify-blob SHA256SUMS.txt \
     --bundle SHA256SUMS.txt.sigstore.json \
     --certificate-identity https://github.com/marbas207/Pathwarden/.github/workflows/sign-sums.yml@refs/heads/main \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

   `Verified OK` means the sums are the ones the workflow signed; then step 1
   ties your archive to them. Releases before 1.0.0-rc.1 have no bundle.

   For archives built locally (scripts/package.ps1), the workflow signs the
   sums of the files it found on the release: the signature shows the
   archives are the ones the release holds and haven't changed since, not
   who built them. That they are this project's comes from the code
   signature (step 4) for the Windows executables, and from provenance
   (step 2) for archives the release workflow built.

4. **Code signature.** The Windows executables (`pathwarden.exe` and both
   plugins) are Authenticode-signed with Azure Artifact Signing.
   `Get-AuthenticodeSignature .\pathwarden.exe` shows Status `Valid` and the
   publisher. Releases built before signing was set up (November 2026) are
   unsigned: `NotSigned`, and SmartScreen may warn about them; use the
   checksum and the signature over the sums.

5. **Contents.** `sbom/` in the archive (and `<archive>.cdx.json` beside it)
   lists every crate built into each executable, with versions and package
   URLs, for your own vulnerability scanner (for example
   `grype sbom:pathwarden-0.2.0-windows-x64-full.cdx.json`).

## Troubleshooting

| Error | Fix |
|---|---|
| `linker 'link.exe' not found` (Windows) | The Visual Studio Build Tools with the C++ workload are missing; install them, then open a new terminal. |
| `failed to find tool. Is 'cc' installed?` (Linux) | Install `build-essential` (Debian/Ubuntu) or `gcc` (RHEL/Fedora). |
| `package ... requires rustc 1.89` or newer, or unknown method `is_multiple_of` | Your Rust is too old: `rustup update stable`. |
| Downloads from crates.io time out behind a corporate proxy | Set `HTTPS_PROXY` (for example `http://proxy.scale.local:8080`), or `[http] proxy` in `~/.cargo/config.toml`. |
| No internet on the build machine | Run `cargo vendor` on a connected machine and copy everything over, with the `.cargo/config.toml` lines it prints. |
| The build is very slow on Windows | Antivirus scanning of `target\` is the usual cause. Exclude the repository's `target` folder if your policy allows, or build on a Dev Drive. |
| The disk fills up | `target\` grows to several GB. `cargo clean` empties it. |
| `error: this Pathwarden build has no built-in collector` | You're running the lean build. Use the full build, or pass `--sharphound PATH` / `--rusthound PATH` to `pathwarden collect`. |
