# Runs clippy for Linux (x86_64-unknown-linux-gnu) from Windows, to catch
# Windows-only code that is dead on Linux (unused imports, never-used helpers)
# before CI does. It checks the full workspace and the lean build, both with
# all targets (tests included) and warnings as errors, like CI.
#
# Needs:
#   rustup target add x86_64-unknown-linux-gnu
#   pip install ziglang          (or zig on PATH, or -Zig C:\path\to\zig.exe)
#
# zig is the C cross compiler for the build scripts of dependencies with C
# code (ring and friends). Clippy doesn't link a Linux binary, so nothing
# else is needed. Tests can't run this way: run them on Linux (CI does).
#
#   powershell -NoProfile -File scripts\linux-check.ps1 [-TargetDir D:\pw-build\linuxcheck] [-Zig path] [-Lean|-Full]
param(
    [string]$TargetDir = '',
    [string]$Zig = '',
    [switch]$Full,
    [switch]$Lean
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$triple = 'x86_64-unknown-linux-gnu'

if (-not $TargetDir) {
    $TargetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }
}

# Find zig: the argument, PATH, or the ziglang Python package.
if (-not $Zig) {
    $cmd = Get-Command zig -ErrorAction SilentlyContinue
    if ($cmd) { $Zig = $cmd.Source }
}
if (-not $Zig) {
    foreach ($py in 'python', 'py') {
        if (Get-Command $py -ErrorAction SilentlyContinue) {
            $dir = & $py -c "import ziglang, os; print(os.path.dirname(ziglang.__file__))" 2>$null
            if ($LASTEXITCODE -eq 0 -and $dir -and (Test-Path (Join-Path $dir 'zig.exe'))) {
                $Zig = Join-Path $dir 'zig.exe'
                break
            }
        }
    }
}
if (-not $Zig) { throw 'zig not found: pip install ziglang, or pass -Zig C:\path\to\zig.exe' }

$installed = & rustup target list --installed
if ($installed -notcontains $triple) { throw "Rust std for $triple is missing: rustup target add $triple" }

# Wrapper scripts, because CC/AR must name a single program. cc-rs passes
# clang's --target=x86_64-unknown-linux-gnu, which zig doesn't understand
# (it wants x86_64-linux-gnu), so the wrapper drops it. The filtering is in
# Python: cmd splits arguments at '=' (-DFOO=1) and the triple also appears
# in output paths, so a batch file can't do it safely.
$python = $null
foreach ($py in 'python', 'py') {
    $c = Get-Command $py -ErrorAction SilentlyContinue
    if ($c) { $python = $c.Source; break }
}
if (-not $python) { throw 'Python is needed for the zig compiler wrapper' }
$wrap = Join-Path $TargetDir 'zig-wrappers'
New-Item -ItemType Directory -Force $wrap | Out-Null
$zigcc = @'
import subprocess, sys
zig, mode = sys.argv[1], sys.argv[2]
args = [a for a in sys.argv[3:] if not a.startswith("--target=")]
sys.exit(subprocess.call([zig, mode, "-target", "x86_64-linux-gnu"] + args))
'@
Set-Content -Encoding ascii (Join-Path $wrap 'zigcc.py') $zigcc
foreach ($mode in 'cc', 'c++') {
    Set-Content -Encoding ascii (Join-Path $wrap "$mode.cmd") "@`"$python`" -I `"%~dp0zigcc.py`" `"$Zig`" $mode %*"
}
Set-Content -Encoding ascii (Join-Path $wrap 'ar.cmd') "@`"$Zig`" ar %*"

$env:CC_x86_64_unknown_linux_gnu = Join-Path $wrap 'cc.cmd'
$env:CXX_x86_64_unknown_linux_gnu = Join-Path $wrap 'c++.cmd'
$env:AR_x86_64_unknown_linux_gnu = Join-Path $wrap 'ar.cmd'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $TargetDir 'zig-cache'
$env:CARGO_TARGET_DIR = $TargetDir

$runFull = $Full -or -not $Lean
$runLean = $Lean -or -not $Full
$failed = @()
if ($runFull) {
    Write-Host "== clippy (full, $triple)"
    & cargo clippy --locked --keep-going --workspace --all-targets --target $triple -- -D warnings
    if ($LASTEXITCODE -ne 0) { $failed += 'full' }
}
if ($runLean) {
    Write-Host "== clippy (lean, $triple)"
    & cargo clippy --locked --keep-going -p pathwarden -p pathwarden-ui --no-default-features --all-targets --target $triple -- -D warnings
    if ($LASTEXITCODE -ne 0) { $failed += 'lean' }
}
if ($failed) { throw "Linux clippy failed: $($failed -join ', ')" }
Write-Host 'Linux clippy: clean'
