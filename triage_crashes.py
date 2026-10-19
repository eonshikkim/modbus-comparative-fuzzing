#!/usr/bin/env python3
"""Group saved crash inputs by root cause.

AFL++ saves a crash whenever the coverage bitmap is new, not whenever
the root cause is new, so the saved-crash count is an upper bound on
the number of distinct defects.

Two independent signals are used, because neither alone is enough:

  Function code. byte 7 of the ADU, which is req[offset] inside
  modbus_reply. In v3.1.10 each unguarded memcpy(rsp, req, req_length)
  sits under a different case, so the function code names the gate:
  0x05 -> modbus.c:905, 0x06 -> :936, 0x16 -> :1058.

  ASan access frame. The frame reported under "WRITE/READ of size N",
  NOT the one under "is located in stack of thread T0 ... in frame",
  which names the function that owns the buffer and therefore always
  resolves to the declaration line of modbus_reply. Mixing the two is
  what makes every crash look like modbus.c:781.

The byte count of the input is deliberately excluded from the
signature: it is req_length, which varies per input and says nothing
about which defect was hit.

    python3 triage_crashes.py [out_dir] [binary]
"""
import collections
import os
import pathlib
import re
import subprocess
import sys

GATES = {0x05: "modbus.c:905 WRITE_SINGLE_COIL",
         0x06: "modbus.c:936 WRITE_SINGLE_REGISTER",
         0x16: "modbus.c:1058 MASK_WRITE_REGISTER"}

HDR = 7          # TCP header_length; req[7] is the function code


def find_crash_dir(out):
    for cand in (f"{out}/default/crashes", f"{out}/crashes"):
        if os.path.isdir(cand):
            return cand
    return None


def parse_report(text):
    """Return (kind, access, frame_owner). access is the frame under the
    WRITE/READ line; frame_owner is the buffer-owning frame."""
    kind = None
    m = re.search(r"AddressSanitizer:\s+([a-z-]+)", text)
    if m:
        kind = m.group(1)

    # The access trace runs from the "WRITE/READ of size" line to the
    # first blank line. Everything after that belongs to the buffer
    # description and must not be read as the faulting frame.
    access = None
    m = re.search(r"(?:WRITE|READ) of size \d+.*?\n(.*?)(?:\n\s*\n|\Z)",
                  text, re.S)
    if m:
        f = re.search(r"in (\S+) (\S*modbus\.c:\d+)", m.group(1))
        if f:
            access = f"{f.group(1)} {os.path.basename(f.group(2))}"

    owner = None
    m = re.search(r"is located in stack of thread.*?\n(.*?)(?:\n\s*\n|\Z)",
                  text, re.S)
    if m:
        f = re.search(r"in (\S+) (\S*modbus\.c:\d+)", m.group(1))
        if f:
            owner = f"{f.group(1)} {os.path.basename(f.group(2))}"

    return kind, access, owner


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "out/v3.1.10_cap1024_wall"
    binary = sys.argv[2] if len(sys.argv) > 2 else "./h_server_v3.1.10_cap1024"

    if not os.access(binary, os.X_OK):
        print(f"error: {binary} not found or not executable", file=sys.stderr)
        return 1
    cdir = find_crash_dir(out)
    if not cdir:
        print(f"error: no crashes directory under {out}", file=sys.stderr)
        return 1

    env = dict(os.environ, ASAN_OPTIONS="symbolize=1:abort_on_error=0")
    rows = []

    for p in sorted(pathlib.Path(cdir).glob("id:*")):
        data = p.read_bytes()
        fc = data[HDR] if len(data) > HDR else None
        gate = GATES.get(fc, f"unmapped fc 0x{fc:02x}" if fc is not None
                         else "input shorter than header")

        try:
            r = subprocess.run([binary, str(p)], env=env, timeout=60,
                               capture_output=True, text=True,
                               errors="replace")
            report = r.stdout + r.stderr
        except subprocess.TimeoutExpired:
            report = ""

        kind, access, owner = parse_report(report)
        rows.append(dict(name=p.name, size=len(data), fc=fc, gate=gate,
                         kind=kind or "no-asan-report",
                         access=access or "(not symbolized)",
                         owner=owner or "(none)"))

    if not rows:
        print(f"no saved crash inputs in {cdir}")
        return 0

    print(f"replayed {len(rows)} saved crash inputs from {cdir}\n")

    sigs = collections.Counter((r["kind"], r["gate"]) for r in rows)
    print(f"distinct defects: {len(sigs)}\n")
    for (kind, gate), n in sigs.most_common():
        print(f"  [{n} input(s)] {kind} @ {gate}")

    acc = collections.Counter(r["access"] for r in rows)
    print(f"\nASan access frames: {len(acc)} distinct")
    for a, n in acc.most_common():
        print(f"  [{n}] {a}")

    own = collections.Counter(r["owner"] for r in rows)
    print(f"\nbuffer-owning frames (expected to be one, the declaration "
          f"line): {len(own)} distinct")
    for o, n in own.most_common():
        print(f"  [{n}] {o}")

    print("\nper input:")
    print(f"  {'bytes':>6}  {'fc':<5} {'gate':<38} input")
    for r in sorted(rows, key=lambda x: x["size"]):
        fc = f"0x{r['fc']:02x}" if r["fc"] is not None else "--"
        print(f"  {r['size']:>6}  {fc:<5} {r['gate']:<38} {r['name'][:34]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
