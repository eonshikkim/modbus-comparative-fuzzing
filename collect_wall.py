#!/usr/bin/env python3
"""Compare the wall-clock runs against the exec-matched campaigns.

Reads AFL++ fuzzer_stats from the *_wall output directories and the
Atheris final stats from wall_pymodbus.log, and prints the two budgets
side by side. The claim under test is that the conclusions do not
depend on which budget was used: same edge count, same crash, despite
roughly two orders of magnitude more executions.

    python3 collect_wall.py
"""
import glob
import pathlib
import re

# Medians from the 300k exec-matched campaigns (Table 1 of the
# milestone). Edges and crashes are what must agree; exec/s and
# execs_done are expected to differ and are shown for context.
BASELINE = {
    "v3.1.10_cap260":  dict(execs=300_000, eps=16_243, edges=132, crashes=0),
    "v3.1.10_cap1024": dict(execs=300_000, eps=16_064, edges=131, crashes=1),
}
PM_BASELINE = dict(cov=113, ft=223)


def read_stats(path):
    d = {}
    for line in pathlib.Path(path).read_text().splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            d[k.strip()] = v.strip()
    return d


def main():
    rows = []
    for stats in sorted(glob.glob("out/*_wall/**/fuzzer_stats", recursive=True)):
        cfg = pathlib.Path(stats).parts[1].replace("_wall", "")
        s = read_stats(stats)
        rows.append((cfg, s))

    if not rows:
        print("no out/*_wall/**/fuzzer_stats found -- run run_wall.sh libmodbus first")
    else:
        hdr = f"{'config':18}{'budget':10}{'execs':>14}{'exec/s':>10}{'edges':>8}{'crashes':>9}"
        print(hdr)
        print("-" * len(hdr))
        for cfg, s in rows:
            base = BASELINE.get(cfg)
            if base:
                print(f"{cfg:18}{'300k':10}{base['execs']:>14,}"
                      f"{base['eps']:>10,}{base['edges']:>8}{base['crashes']:>9}")
            execs = int(float(s.get("execs_done", 0)))
            eps = float(s.get("execs_per_sec", 0))
            edges = int(float(s.get("edges_found", 0)))
            crashes = int(float(s.get("saved_crashes",
                                      s.get("unique_crashes", 0))))
            print(f"{cfg:18}{'30 min':10}{execs:>14,}"
                  f"{eps:>10,.0f}{edges:>8}{crashes:>9}")
            if base:
                ok_e = "same" if edges == base["edges"] else \
                       f"DIFFERS ({base['edges']} -> {edges})"
                ok_c = "same" if crashes == base["crashes"] else \
                       f"DIFFERS ({base['crashes']} -> {crashes})"
                ratio = execs / base["execs"] if base["execs"] else 0
                print(f"{'':18}{'':10}{ratio:>13.0f}x"
                      f"{'':10}{ok_e:>8}{ok_c:>9}")
            print()

    log = pathlib.Path("wall_pymodbus.log")
    if log.exists():
        text = log.read_text()
        cov = ft = execs = None
        for m in re.finditer(r"cov:\s*(\d+)\s+ft:\s*(\d+)", text):
            cov, ft = int(m.group(1)), int(m.group(2))
        m = re.search(r"stat::number_of_executed_units:\s*(\d+)", text)
        if m:
            execs = int(m.group(1))
        print("pymodbus server")
        print(f"  300k budget   cov {PM_BASELINE['cov']}  ft {PM_BASELINE['ft']}")
        if cov is None:
            print("  30 min        no cov:/ft: line found in wall_pymodbus.log")
        else:
            note = "same" if cov == PM_BASELINE["cov"] else \
                   f"DIFFERS ({PM_BASELINE['cov']} -> {cov})"
            ex = f"  execs {execs:,}" if execs else ""
            print(f"  30 min        cov {cov}  ft {ft}{ex}   cov {note}")
    else:
        print("wall_pymodbus.log not found -- run run_wall.sh pymodbus")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
