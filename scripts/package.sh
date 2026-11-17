#!/bin/sh
# Builds both Pathwarden variants and packages each as a tar.gz in dist/:
#   pathwarden-<version>-linux-x64-full.tar.gz  (built-in collector)
#   pathwarden-<version>-linux-x64-lean.tar.gz  (no built-in collector)
# (linux-x64-musl-* with --target x86_64-unknown-linux-musl: static binaries.)
# Each holds pathwarden, the ServiceNow and Jira plugins, the license, the
# notices, THIRD-PARTY-LICENSES.md (every crate's license text, from
# cargo-about), CycloneDX SBOMs of the three executables (sbom/), the README
# and the example configuration: the layout of the Windows zips
# (scripts/package.ps1). Next to each archive goes its SBOM
# (<archive name>.cdx.json), and dist/SHA256SUMS.txt is written fresh with
# the hashes of exactly this run's files.
#
# Builds use Cargo.lock as committed (--locked) and the toolchain that
# rust-toolchain.toml pins. The script refuses to package a working tree
# with uncommitted changes, so an archive always matches a commit; --force
# packages anyway (for a local test build).
#
# Needs cargo-about and cargo-cyclonedx:
#   cargo install cargo-about --locked --features cli
#   cargo install cargo-cyclonedx --locked
#
#   sh scripts/package.sh [--force] [--target TRIPLE] [--out-dir DIR]
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)

force=0
target=""
dist=dist
while [ $# -gt 0 ]; do
    case "$1" in
        --force) force=1 ;;
        --target) target=$2; shift ;;
        --out-dir) dist=$2; shift ;;
        *) echo "usage: sh scripts/package.sh [--force] [--target TRIPLE] [--out-dir DIR]" >&2; exit 2 ;;
    esac
    shift
done

# Uncommitted changes (ignored files such as target/ and dist/ don't count).
if ! dirty=$(git status --porcelain 2>/dev/null); then
    if [ "$force" -ne 1 ]; then
        echo "error: not a git checkout, so the source state is unknown; run with --force to package anyway" >&2
        exit 1
    fi
    echo "warning: not a git checkout; packaging anyway (--force)" >&2
elif [ -n "$dirty" ]; then
    if [ "$force" -ne 1 ]; then
        printf 'error: the working tree has uncommitted changes:\n%s\nCommit or stash them, or run with --force for a test build.\n' "$dirty" >&2
        exit 1
    fi
    echo "warning: the working tree has uncommitted changes; packaging anyway (--force)" >&2
fi

for tool in about cyclonedx; do
    if ! cargo "$tool" --version > /dev/null 2>&1; then
        echo "error: cargo $tool is missing; see the comment at the top of this script" >&2
        exit 1
    fi
done

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
host=$(rustc -vV | sed -n 's/^host: //p')
triple=${target:-$host}
arch=$(echo "$triple" | cut -d- -f1 | sed 's/x86_64/x64/; s/aarch64/arm64/')
case "$triple" in
    *-musl) platform="linux-$arch-musl" ;;
    *) platform="linux-$arch" ;;
esac
target_args=""
bin_sub=release
if [ -n "$target" ]; then
    target_args="--target $target"
    bin_sub="$target/release"
fi
# SBOM timestamps from the commit, so a rebuild gives the same SBOM.
if commit_time=$(git log -1 --format=%ct 2>/dev/null); then
    export SOURCE_DATE_EPOCH="$commit_time"
fi

mkdir -p "$dist"
dist=$(cd "$dist" && pwd)
rm -f "$dist/SHA256SUMS.txt"
sums=$(mktemp)
part=$(mktemp)
sbom_tag="pathwarden-package-sbom-$$"
trap 'rm -f "$sums" "$part" crates/*/"$sbom_tag".json' EXIT

# sh functions share every variable with their caller: licenses() and
# sboms() use names of their own, never package()'s (variant, bin,
# features, name, stage).

# THIRD-PARTY-LICENSES.md: the license texts of every crate built into each
# executable (cargo-about, about.toml, about.hbs). $1: pathwarden's feature
# flags.
licenses() {
    out=$2
    {
        printf '# Third-party licenses: Rust crates\n\n'
        printf 'The license texts of the Rust crates built into this release, per executable, generated from\n'
        printf 'Cargo.lock by cargo-about (https://github.com/EmbarkStudios/cargo-about). THIRD-PARTY-NOTICES.md\n'
        printf 'covers the rest: RustHound-CE, the BloodHound Query Library, Cytoscape.js, the modified ldap3\n'
        printf 'and smb2-client, and the WebView2 loader.\n'
    } > "$out"
    for exe in pathwarden pathwarden-output-servicenow pathwarden-output-jira; do
        if [ "$exe" = pathwarden ]; then
            # shellcheck disable=SC2086
            cargo about generate --locked --fail -m crates/pathwarden-cli/Cargo.toml --target "$triple" -o "$part" $1 about.hbs
        else
            cargo about generate --locked --fail -m "crates/$exe/Cargo.toml" --target "$triple" -o "$part" about.hbs
        fi
        printf '\n## %s\n\n' "$exe" >> "$out"
        cat "$part" >> "$out"
    done
}

# CycloneDX SBOMs (JSON, spec 1.5) of the three executables, with local
# paths replaced so they don't name the build machine's folders.
sboms() {
    # shellcheck disable=SC2086
    cargo cyclonedx -f json --spec-version 1.5 --target "$triple" --override-filename "$sbom_tag" -q $1
    mkdir -p "$2"
    for crate in pathwarden-cli pathwarden-output-servicenow pathwarden-output-jira; do
        # Not `name`: sh has no local variables, and package() uses that one.
        sbom_name=$crate
        [ "$crate" = pathwarden-cli ] && sbom_name=pathwarden
        sed "s|file://$root|file:///pathwarden|g; s|$root|pathwarden|g" "crates/$crate/$sbom_tag.json" > "$2/$sbom_name.cdx.json"
    done
    rm -f crates/*/"$sbom_tag".json
}

package() {
    variant=$1
    bin=$2
    features=$3
    name="pathwarden-$version-$platform-$variant"
    stage="$dist/$name"
    rm -rf "$stage"
    mkdir -p "$stage"
    cp "$bin/pathwarden" "$bin/pathwarden-output-servicenow" "$bin/pathwarden-output-jira" "$stage/"
    shown=$("$stage/pathwarden" --version)
    if [ "$shown" != "pathwarden $version" ]; then
        echo "error: $variant build says '$shown', expected 'pathwarden $version'" >&2
        exit 1
    fi
    cp LICENSE THIRD-PARTY-NOTICES.md README.md pathwarden.example.toml "$stage/"
    echo "  writing THIRD-PARTY-LICENSES.md and the SBOMs..."
    licenses "$features" "$stage/THIRD-PARTY-LICENSES.md"
    sboms "$features" "$stage/sbom"
    # Run on a domain admin's Windows machine, whatever the collector's OS.
    mkdir -p "$stage/scripts"
    cp scripts/collector/*.ps1 "$stage/scripts/"
    tar -C "$dist" -czf "$dist/$name.tar.gz" "$name"
    cp "$stage/sbom/pathwarden.cdx.json" "$dist/$name.cdx.json"
    rm -rf "$stage"
    (cd "$dist" && sha256sum "$name.tar.gz" "$name.cdx.json") >> "$sums"
    echo "  $dist/$name.tar.gz"
}

echo "Building full ($triple)..."
# shellcheck disable=SC2086
cargo build --release --locked $target_args -p pathwarden -p pathwarden-output-servicenow -p pathwarden-output-jira
package full "target/$bin_sub" ""

echo "Building lean ($triple)..."
# shellcheck disable=SC2086
cargo build --release --locked $target_args -p pathwarden --no-default-features --target-dir target/lean
# shellcheck disable=SC2086
cargo build --release --locked $target_args -p pathwarden-output-servicenow -p pathwarden-output-jira --target-dir target/lean
package lean "target/lean/$bin_sub" "--no-default-features"

# One fresh file with exactly this run's files.
cp "$sums" "$dist/SHA256SUMS.txt"
echo "Unsigned: Linux executables are not signed; the release workflow records build provenance."
echo "Done: $dist/"
