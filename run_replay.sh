#!/usr/bin/env bash
# Cross-implementation replay. Run the libmodbus half in the AFL++
# container and the pymodbus half in the python container, then merge.
#
#   ./run_replay.sh libmodbus     (in the AFL++ container)
#   ./run_replay.sh pymodbus      (in the python container)
#   python3 merge_replay.py
#
# Must be run inside a container, from /work. Running it on the host
# will fail: the libmodbus archives are Linux x86_64 objects.
set -u

SIDE="${1:-}"
IN=replay_inputs

if [ ! -d /work ] && [ "$SIDE" = "libmodbus" ]; then
  echo "error: /work not found. Run this inside the AFL++ container:" >&2
  echo "  docker exec -it <afl-container> bash" >&2
  echo "  cd /work" >&2
  exit 1
fi

if [ ! -f replay_libmodbus.c ] && [ "$SIDE" = "libmodbus" ]; then
  echo "error: replay_libmodbus.c not found in $(pwd)" >&2
  exit 1
fi

if [ ! -d "$IN" ]; then
  echo "generating input set"
  python3 mkprobes.py
fi

run_one() {           # $1 = label, rest = command
  local label="$1"; shift
  local out="replay_${label}.tsv"
  : > "$out"
  local f name line rc
  for f in $(find "$IN" -name '*.bin' | sort); do
    name="${f#$IN/}"
    line=$("$@" "$f" 2>/dev/null)
    rc=$?
    if [ $rc -eq 134 ] || [ $rc -eq 139 ]; then
      line=$'CRASH\tsignal exit '"$rc"
    elif [ -z "$line" ]; then
      line=$'ERROR\tno output, exit '"$rc"
    fi
    printf '%s\t%s\n' "$name" "$line" >> "$out"
  done
  echo "wrote $out ($(wc -l < "$out") rows)"
}

case "$SIDE" in
  libmodbus)
    command -v afl-clang-fast >/dev/null || {
      echo "error: afl-clang-fast not found. Wrong container?" >&2; exit 1; }
    for v in v3.1.10 v3.2.0; do
      if [ ! -f "lib-$v/src/.libs/libmodbus.a" ]; then
        echo "skipping $v: lib-$v/src/.libs/libmodbus.a not built"
        continue
      fi
      for cap in 260 1024; do
        bin="replay_lm_${v}_cap${cap}"
        # Rebuild when the driver source is newer, otherwise a stale
        # binary from an earlier run silently wins.
        if [ ! -x "$bin" ] || [ replay_libmodbus.c -nt "$bin" ]; then
          echo "building $bin"
          # The archives carry afl-clang-fast instrumentation, so the
          # driver must be linked with afl-clang-fast too. Plain clang
          # leaves __afl_area_ptr and friends undefined. No
          # -fsanitize=fuzzer here: this driver has its own main().
          AFL_USE_ASAN=1 afl-clang-fast -g -O1 -fno-omit-frame-pointer \
            -DREQ_CAP=$cap \
            -I "lib-$v/src" replay_libmodbus.c \
            "lib-$v/src/.libs/libmodbus.a" -o "$bin" || {
              echo "build failed for $bin"; continue; }
        fi
        ASAN_OPTIONS=abort_on_error=1:symbolize=0 \
          run_one "lm_${v}_cap${cap}" "./$bin"
      done
    done
    ;;
  pymodbus)
    python3 -c "import pymodbus" 2>/dev/null || {
      echo "error: pymodbus not importable. Wrong container?" >&2; exit 1; }
    PM_SIDE=server run_one "pm_server" python3 replay_pymodbus.py
    PM_SIDE=client run_one "pm_client" python3 replay_pymodbus.py
    ;;
  *)
    echo "usage: $0 {libmodbus|pymodbus}" >&2
    exit 2
    ;;
esac
