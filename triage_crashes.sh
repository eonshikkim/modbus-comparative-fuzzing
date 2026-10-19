#!/usr/bin/env bash
# Group the saved crash inputs by root cause.
#
#   ./triage_crashes.sh
#
# AFL++ saves a crash whenever the coverage bitmap is new, not whenever
# the root cause is new, so N saved crashes is an upper bound on the
# number of distinct defects. This replays each saved input under the
# ASan-instrumented harness and groups them by the fault type plus the
# first frame inside libmodbus. Inputs that share a signature are the
# same defect reached by different paths.
#
# Must be run inside the AFL++ container, from /work.
set -u

OUT="${1:-out/v3.1.10_cap1024_wall}"
BIN="${2:-./h_server_v3.1.10_cap1024}"
SIGS=".triage_sigs"

if [ ! -x "$BIN" ]; then
  echo "error: $BIN not found" >&2; exit 1
fi

# AFL++ writes crashes to <out>/default/crashes when no -M/-S is used,
# and to <out>/crashes otherwise. Accept either.
DIR=""
for cand in "$OUT/default/crashes" "$OUT/crashes"; do
  [ -d "$cand" ] && DIR="$cand" && break
done
if [ -z "$DIR" ]; then
  echo "error: no crashes directory under $OUT" >&2; exit 1
fi

: > "$SIGS"
n=0

for f in "$DIR"/id:*; do
  [ -f "$f" ] || continue
  case "$(basename "$f")" in README*) continue;; esac
  n=$((n + 1))

  rpt=$(ASAN_OPTIONS=symbolize=1:abort_on_error=0 "$BIN" "$f" 2>&1)

  kind=$(printf '%s\n' "$rpt" \
         | grep -m1 -oE 'AddressSanitizer: [a-z-]+' | sed 's/.*: //')
  size=$(printf '%s\n' "$rpt" \
         | grep -m1 -oE '(WRITE|READ) of size [0-9]+')
  # First stack frame that lands inside libmodbus itself.
  frame=$(printf '%s\n' "$rpt" \
          | grep -m1 -oE 'in [A-Za-z_][A-Za-z0-9_]* [^ ]*modbus\.c:[0-9]+' \
          | sed 's/^in //')

  [ -z "$kind" ]  && kind="no-asan-report"
  [ -z "$frame" ] && frame="(no libmodbus frame)"

  printf '%s | %s | %s\t%s\t%s\n' \
    "$kind" "$frame" "$size" "$(basename "$f")" "$(wc -c < "$f")" >> "$SIGS"
done

echo "replayed $n saved crash inputs from $DIR"
echo

sigs=$(cut -f1 "$SIGS" | sort -u | wc -l | tr -d ' ')
echo "distinct signatures: $sigs"
echo

cut -f1 "$SIGS" | sort | uniq -c | sort -rn | while read -r count sig; do
  echo "  [$count input(s)] $sig"
done

echo
echo "per input (signature / file / bytes):"
sort "$SIGS" | while IFS=$'\t' read -r sig file bytes; do
  printf '  %-6s %-28s %s\n' "${bytes}B" "$file" "$sig"
done

rm -f "$SIGS"
