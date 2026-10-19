#!/usr/bin/env bash
# Wall-clock cross-check. Confirms that the 300k exec-matched budget is
# not driving the conclusions.
#
#   ./run_wall.sh libmodbus     (AFL++ container, ~60 min, 2 configs)
#   ./run_wall.sh pymodbus      (python container, ~30 min, 1 config)
#   python3 collect_wall.py
#
# Run the two sides SEQUENTIALLY, never at the same time. Two fuzzers on
# one machine compete for CPU and the exec/s comparison stops meaning
# anything.
#
# Progress is written to wall_<side>.log in /work, which is bind-mounted,
# so it can be tailed from the host without attaching to the container.
set -u

SIDE="${1:-}"
SECS="${WALL_SECS:-1800}"
LOG="wall_${SIDE}.log"

say() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

if [ ! -d /work ]; then
  echo "error: /work not found. Run this inside a container:" >&2
  echo "  docker exec -d -w /work <container> ./run_wall.sh $SIDE" >&2
  exit 1
fi

case "$SIDE" in
  libmodbus)
    command -v afl-fuzz >/dev/null || {
      echo "error: afl-fuzz not found. Wrong container?" >&2; exit 1; }

    export AFL_SKIP_CPUFREQ=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_NO_AFFINITY=1
    # Plain status lines instead of the TUI, so the redirected log stays
    # readable rather than filling with terminal escape sequences.
    export AFL_NO_UI=1

    : > "$LOG"
    say "wall-clock run, ${SECS}s per config, 2 configs"

    for cap in 260 1024; do
      bin="./h_server_v3.1.10_cap${cap}"
      out="out/v3.1.10_cap${cap}_wall"

      if [ ! -x "$bin" ]; then
        say "SKIP cap${cap}: $bin not found -- rebuild it from RUN.md section 3"
        continue
      fi
      # A pre-existing output dir makes AFL++ resume the old session
      # instead of starting a clean one, which would invalidate the
      # comparison.
      if [ -d "$out" ]; then
        say "SKIP cap${cap}: $out already exists -- remove it to re-run"
        continue
      fi

      say "START cap${cap} -> $out"
      # -V is a wall-clock limit in seconds, unlike the -E exec limit
      # used for the matched-budget campaigns.
      afl-fuzz -i seeds -o "$out" -s 1 -x modbus.dict \
               -V "$SECS" -m none -- "$bin" >> "$LOG" 2>&1
      say "DONE cap${cap} (afl exit $?)"
    done
    say "libmodbus side finished"
    ;;

  pymodbus)
    python3 -c "import atheris, pymodbus" 2>/dev/null || {
      echo "error: atheris/pymodbus not importable. Wrong container?" >&2
      exit 1; }

    : > "$LOG"
    say "wall-clock run, ${SECS}s, pymodbus server"

    if [ -d corpus_py_wall ]; then
      say "SKIP: corpus_py_wall already exists -- remove it to re-run"
    else
      mkdir -p corpus_py_wall
      say "START pm_server -> corpus_py_wall"
      # -max_len is required. Without it libFuzzer infers the cap from
      # the seed sizes and barely generates long frames.
      PM_SIDE=server python3 harness_py.py \
        -max_total_time="$SECS" -max_len=600 -print_final_stats=1 \
        corpus_py_wall seeds_py >> "$LOG" 2>&1
      say "DONE pm_server (exit $?)"
    fi
    say "pymodbus side finished"
    ;;

  *)
    echo "usage: $0 {libmodbus|pymodbus}" >&2
    exit 2
    ;;
esac
