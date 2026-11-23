#!/usr/bin/env bash
# Cross-compile the JARVIS desktop Windows binary from WSL.
#
#   desktop/scripts/build-windows.sh [--check-only] [--force] [--test]
#
# --test compiles the app's unit tests for Windows instead of the app and runs
# them natively on Windows (from %LOCALAPPDATA%\JarvisDesktopBuild\tests): CI
# runs these tests on Linux only, so this is where the cfg(windows) paths run.
#
# Why not build on Windows: Defender's ASR rule 01443614 ("block executables unless
# they meet a prevalence, age or trusted-list criterion") is in block mode here and
# blocks every freshly built cargo build script (measured 2026-10-23: event 1121,
# "Access is denied"). Here the build scripts run as Linux programs, so no Windows
# exclusion is needed to build. The finished binary was not blocked when launched
# from %LOCALAPPDATA% (measured 2026-10-23); install.ps1 checks for a block on launch.
#
# The toolchain is what is already on this machine, nothing downloaded:
#   rustc's x86_64-pc-windows-msvc std (rustup target), rust-lld as the linker,
#   clang (as clang-cl) and llvm-rc/llvm-lib from LLVM 18, and the MSVC and Windows
#   SDK libraries/headers of the Visual Studio Build Tools on C:.
#
# Bounded: refuses unless the machine is idle (load, available memory, C: space),
# builds at nice 19 / idle I/O with -j 2, and stops the build if available memory
# stays under the floor. Writes the binary and build-receipt.json to
# %LOCALAPPDATA%\JarvisDesktopBuild for install.ps1, which checks the hash.
set -euo pipefail

TARGET=x86_64-pc-windows-msvc
JOBS=${JOBS:-2}
MAX_LOAD_PER_CPU=${MAX_LOAD_PER_CPU:-0.5}   # 1-minute load average / CPUs
MIN_AVAIL_MB=${MIN_AVAIL_MB:-3000}          # to start
ABORT_AVAIL_MB=${ABORT_AVAIL_MB:-700}       # stop the build below this for 15 s
MIN_C_FREE_GB=${MIN_C_FREE_GB:-8}

DESKTOP=$(cd "$(dirname "$0")/.." && pwd)
SHIM=${XWIN_SHIM:-$HOME/.cache/jarvis-xwin}
VS="/mnt/c/Program Files (x86)/Microsoft Visual Studio"
KITS="/mnt/c/Program Files (x86)/Windows Kits/10"
LLVM=/usr/lib/llvm-18/bin
RUST_LLD=$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld

check_only=0 force=0 test_mode=0
for a in "$@"; do
  case $a in
    --check-only) check_only=1 ;;
    --test) test_mode=1 ;;
    --force) force=1 ;;
    *) echo "unknown argument: $a" >&2; exit 64 ;;
  esac
done

die() { echo "build-windows: $*" >&2; exit 1; }
avail_mb() { awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo; }

# 1. Idle gate.
cpus=$(nproc)
load=$(cut -d' ' -f1 /proc/loadavg)
avail=$(avail_mb)
cfree=$(df -BG --output=avail /mnt/c | tail -1 | tr -dc 0-9)
echo "Readings: load ${load} on ${cpus} CPUs, available memory ${avail} MB, C: free ${cfree} GB"
why=()
awk -v l="$load" -v c="$cpus" -v m="$MAX_LOAD_PER_CPU" 'BEGIN { exit !(l / c > m) }' \
  && why+=("load ${load} > $(awk -v c="$cpus" -v m="$MAX_LOAD_PER_CPU" 'BEGIN {print c*m}')")
(( avail < MIN_AVAIL_MB )) && why+=("available memory ${avail} MB < ${MIN_AVAIL_MB} MB")
(( cfree < MIN_C_FREE_GB )) && why+=("C: free ${cfree} GB < ${MIN_C_FREE_GB} GB")
if (( ${#why[@]} )); then
  if (( force && !check_only )); then
    echo "Building despite: ${why[*]} (--force)"
  else
    echo "Not building: the machine is not idle (${why[*]})."; exit 2
  fi
fi

# 2. The interface bundle must be current: cargo embeds ui/dist as it is.
[[ -f $DESKTOP/ui/dist/index.html ]] || die "no ui/dist; run: cd desktop/ui && bun run build"
newer=$(find "$DESKTOP/ui/src" "$DESKTOP/ui/index.html" -newer "$DESKTOP/ui/dist/index.html" -type f | head -1)
[[ -z $newer ]] || die "ui/dist is older than $newer; run: cd desktop/ui && bun run build"

# 3. Toolchain present.
rustup target list --installed | grep -qx $TARGET || die "missing std: rustup target add $TARGET"
[[ -x $RUST_LLD ]] || die "rust-lld not found at $RUST_LLD"
for t in clang llvm-rc llvm-lib; do
  [[ -x $LLVM/$t || -x /usr/bin/$t ]] || die "missing $t (LLVM 18)"
done
msvc=$(ls -d "$VS"/2022/*/VC/Tools/MSVC/*/ 2>/dev/null | sort -V | tail -1)
[[ -n $msvc ]] || die "no MSVC tools under $VS"
sdk=$(ls -d "$KITS"/Lib/*/um/x64 2>/dev/null | sort -V | tail -1 | sed 's#/um/x64$##')
[[ -n $sdk ]] || die "no Windows SDK libraries under $KITS/Lib"
sdkver=$(basename "$sdk")
echo "Toolchain: $(rustc -V), MSVC $(basename "$msvc"), SDK $sdkver"
(( check_only )) && { echo "Checks passed; not building (--check-only)."; exit 0; }

# Space-free links to the Windows libraries and headers (RUSTFLAGS and CFLAGS split
# on spaces). /mnt/c lookups are case-insensitive, which the SDK's mixed-case
# includes rely on.
mkdir -p "$SHIM/bin" "$SHIM/lib" "$SHIM/include"
ln -sfn "$LLVM/clang" "$SHIM/bin/clang-cl"
ln -sfn "${msvc%/}/lib/x64" "$SHIM/lib/msvc"
ln -sfn "$sdk/ucrt/x64" "$SHIM/lib/ucrt"
ln -sfn "$sdk/um/x64" "$SHIM/lib/um"
ln -sfn "${msvc%/}/include" "$SHIM/include/msvc"
for d in ucrt um shared winrt; do ln -sfn "$KITS/Include/$sdkver/$d" "$SHIM/include/$d"; done

export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=$RUST_LLD
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="-Lnative=$SHIM/lib/msvc -Lnative=$SHIM/lib/ucrt -Lnative=$SHIM/lib/um"
export CC_x86_64_pc_windows_msvc=$SHIM/bin/clang-cl
export CXX_x86_64_pc_windows_msvc=$SHIM/bin/clang-cl
export AR_x86_64_pc_windows_msvc=$LLVM/llvm-lib
export RC_x86_64_pc_windows_msvc=$LLVM/llvm-rc
inc=""; for d in msvc ucrt um shared winrt; do inc+=" /imsvc $SHIM/include/$d"; done
export CFLAGS_x86_64_pc_windows_msvc="--target=x86_64-pc-windows-msvc$inc"
export CXXFLAGS_x86_64_pc_windows_msvc="$CFLAGS_x86_64_pc_windows_msvc"
export INCLUDE="$SHIM/include/msvc;$SHIM/include/ucrt;$SHIM/include/um;$SHIM/include/shared;$SHIM/include/winrt"

# 4. Build, lowest priority, watching available memory.
logdir=$DESKTOP/target/$TARGET/logs
mkdir -p "$logdir"
log=$logdir/build-$(date -u +%Y%m%dT%H%M%SZ).log
start=$(date +%s)
cd "$DESKTOP"
if (( test_mode )); then
  # Debug test binary for Windows, then run it there. Same idle checks, niceness
  # and memory floor as the app build, without the watchdog loop: tests compile once.
  nice -n 19 ionice -c3 cargo test --no-run --locked -j "$JOBS" --target $TARGET --message-format=json >"$log" 2>"$log.err" \
    || { tail -30 "$log.err"; die "test build failed. Log: $log.err"; }
  texe=$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    try: m = json.loads(l)
    except ValueError: continue
    if m.get("reason") == "compiler-artifact" and m.get("profile", {}).get("test") and m.get("executable"):
        print(m["executable"])' "$log" | tail -1)
  [[ -f $texe ]] || die "no test executable in $log"
  winlocal=$(wslpath "$(powershell.exe -NoProfile -Command '[Environment]::GetFolderPath("LocalApplicationData")' | tr -d '\r')")
  tdir=$winlocal/JarvisDesktopBuild/tests
  mkdir -p "$tdir"
  cp -f "$texe" "$tdir/jarvis-desktop-tests.exe"
  echo "Running the unit tests on Windows: $(wslpath -w "$tdir/jarvis-desktop-tests.exe")"
  # Run from the Windows folder so the process starts with a Windows working directory.
  (cd "$tdir" && ./jarvis-desktop-tests.exe --test-threads=2 2>&1) | tee "$logdir/windows-tests-$(date -u +%Y%m%dT%H%M%SZ).log"
  rc=${PIPESTATUS[0]}
  # 126/"Invalid argument": Windows refused to start it. On the owner's machine that is
  # Defender ASR rule 01443614 (prevalence) blocking a fresh build (event 1121); this
  # script does not work around Windows policy, it says so.
  if (( rc == 126 || rc == 1 )) && powershell.exe -NoProfile -Command \
      "Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 20 | Where-Object { \$_.Id -eq 1121 -and \$_.TimeCreated -gt (Get-Date).AddMinutes(-5) -and \$_.Message -like '*jarvis-desktop-tests.exe*' } | Select-Object -First 1" \
      2>/dev/null | grep -q 1121; then
    echo "Windows did not run the tests: Defender attack surface reduction rule 01443614 blocked the new test binary (event 1121). Not a test failure; nothing was bypassed." >&2
    exit 126
  fi
  exit "$rc"
fi

nice -n 19 ionice -c3 cargo build --release --locked -j "$JOBS" --target $TARGET \
  --features custom-protocol >"$log" 2>&1 &
pid=$!
low=0 min_avail=$avail aborted=""
while kill -0 $pid 2>/dev/null; do
  sleep 5
  a=$(avail_mb); (( a < min_avail )) && min_avail=$a
  if (( a < ABORT_AVAIL_MB )); then low=$((low + 1)); else low=0; fi
  if (( low >= 3 )); then
    aborted="available memory stayed under ${ABORT_AVAIL_MB} MB for 15 s"
    pkill -TERM -P $pid 2>/dev/null || true; kill -TERM $pid 2>/dev/null || true
    break
  fi
done
code=0; wait $pid || code=$?
minutes=$(awk -v s=$(( $(date +%s) - start )) 'BEGIN {printf "%.1f", s/60}')
if [[ -n $aborted ]]; then echo "Build stopped: $aborted. Log: $log"; exit 3; fi
if (( code )); then tail -30 "$log"; echo "cargo failed (exit $code) after $minutes min. Log: $log"; exit $code; fi

# 5. Hand over to Windows with a receipt.
exe=$DESKTOP/target/$TARGET/release/jarvis-desktop.exe
[[ -f $exe ]] || die "cargo succeeded but $exe is missing"
winlocal=$(wslpath "$(powershell.exe -NoProfile -Command '[Environment]::GetFolderPath("LocalApplicationData")' | tr -d '\r')")
out=$winlocal/JarvisDesktopBuild
mkdir -p "$out"
cp -f "$exe" "$out/jarvis-desktop.exe"
cp -f "$DESKTOP/icons/128x128@2x.png" "$out/jarvis.png"
sha=$(sha256sum "$out/jarvis-desktop.exe" | cut -d' ' -f1)
[[ $sha == $(sha256sum "$exe" | cut -d' ' -f1) ]] || die "copy to $out does not match the build"
commit=$(git -C "$DESKTOP" rev-parse --short HEAD 2>/dev/null || echo unknown)
# Outside a git checkout (a renamed copy) there is nothing to count: 0, not a failure.
dirty=$( (git -C "$DESKTOP" status --porcelain -- . 2>/dev/null || true) | wc -l)
python3 - "$out/build-receipt.json" <<EOF
import json, sys
json.dump({
    "built_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "sha256": "$sha",
    "bytes": $(stat -c %s "$exe"),
    "minutes": $minutes,
    "target": "$TARGET",
    "rustc": "$(rustc -V)",
    "msvc": "$(basename "$msvc")",
    "sdk": "$sdkver",
    "features": "custom-protocol",
    "jobs": $JOBS,
    "commit": "$commit",
    "uncommitted_desktop_files": $dirty,
    "readings_before": {"load": $load, "cpus": $cpus, "avail_mb": $avail, "c_free_gb": $cfree},
    "min_avail_mb": $min_avail,
    "forced": bool($force),
}, open(sys.argv[1], "w"), indent=2)
EOF
echo "Built jarvis-desktop.exe ($(( $(stat -c %s "$exe") / 1024 )) KB) in $minutes min; lowest available memory ${min_avail} MB."
echo "SHA-256 $sha"
echo "Handed over to $(wslpath -w "$out"). Next, from a normal (not elevated) PowerShell:"
echo "  powershell -NoProfile -ExecutionPolicy Bypass -File \\\\wsl.localhost\\Ubuntu${DESKTOP//\//\\}\\scripts\\windows\\install.ps1"
