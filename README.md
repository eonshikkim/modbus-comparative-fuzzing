# Same Specification, Different Attack Surface

Comparative fuzzing of two independent Modbus TCP server implementations:
**libmodbus** (C) and **pymodbus** (Python). Both implement the same
public specification, so differences in what they accept, reject, or
crash on come from the implementations rather than from the protocol.

CIS 6614 group project, University of Central Florida.

## Results

- **CVE-2024-10918 reproduced.** `modbus_reply` in libmodbus v3.1.10
  copies `req_length` bytes into `uint8_t rsp[260]` unchecked. Minimized
  proof-of-concept: 261 bytes. Patched in v3.1.11.
- **The same defect sits in three branches, not one.** The identical
  unvalidated copy appears at `modbus.c:905` (FC 0x05), `:936` (FC 0x06)
  and `:1058` (FC 0x16). The CVE write-up cites one. A 300k-execution
  campaign found 0x16; a 30-minute campaign found all three.
- **The threat model decides reachability.** Bound `req_length` at 260,
  what the network path can deliver: 29,377,732 executions, zero
  crashes. Bound it at 1024, modeling a caller that supplies its own
  length: immediate crash. Same library, same input, same build.
- **pymodbus crash counts are N/A, not 0.** `pdu/decoders.py:93`
  swallows the fault class that crashes the C implementation, so an
  exception-based oracle cannot see it. Removing the whitelist entirely
  still produced no uncaught exception in 5,000 executions.
- **27 shared inputs, 6 configurations, 17 diverge.** libmodbus ignores
  the MBAP length field; pymodbus reads it and then stalls waiting for
  bytes that never arrive. On malformed PDUs the usual narrative
  inverts — libmodbus rejects all of them, pymodbus accepts some.

## Layout

| Path | What it is |
|---|---|
| `harness.c` | libmodbus server harness (`modbus_reply`), `REQ_CAP` selects the threat model |
| `harness_client.c` | libmodbus client harness, 9 response-parsing APIs |
| `harness_py.py` | pymodbus server harness (Atheris) |
| `harness_py_client.py` | pymodbus client harness (Atheris) |
| `mkprobes.py` | generates the 27 shared replay inputs |
| `replay_libmodbus.c` | replay driver, classifies ACCEPT / EXCEPTION / DROP / ERROR |
| `replay_pymodbus.py` | replay driver, classifies ACCEPT / REJECT / DROP / INCOMPLETE / ERROR |
| `run_replay.sh` | builds and runs both replay halves |
| `merge_replay.py` | merges the replay TSVs into a comparison table |
| `run_wall.sh` | wall-clock cross-check against the exec-matched budget |
| `collect_wall.py` | compares the two budgets |
| `triage_crashes.py` | groups saved crash inputs by root cause |
| `seeds/`, `modbus.dict` | AFL++ seed corpus and dictionary |
| `artifacts/crashes/` | the five wall-clock crash inputs, named for the gate each enters |
| `min.bin` | minimized CVE-2024-10918 proof-of-concept, 261 bytes |
| `replay_*.tsv` | per-configuration replay results |
| `RUN.md` | full reproduction procedure, sections 0–10 |

## Reproducing

See `RUN.md`. Two containers are used: `aflplusplus/aflplusplus` for
the C side and `python:3.11` for the Python side, both with the
working directory bind-mounted at `/work`.

Three details cost us whole campaigns and are worth repeating:

- `AFL_USE_ASAN=1` must be set on `./configure`, not only when linking
  the harness. Stack redzones are placed at compile time, so an
  uninstrumented library silently absorbs the overflow: 630,698 clean
  executions before we caught this, seconds to crash afterwards.
- `modbus_set_response_timeout(ctx, 0, 1)` is required. Since v3.1.x
  the flush path in `response_exception()` sleeps for the response
  timeout, 500 ms by default, and most mutated inputs take an
  exception branch. Before setting it: 159 executions in 63 seconds.
  After: 537,597 in 31 seconds.
- The request buffer must be zeroed between executions. Without it,
  stale bytes from the previous input decide branches for the current
  one and nothing reproduces.

## Scope

Everything here targets published, already-patched defects in
open-source libraries, on loopback, in containers. No network service
is attacked and no unpatched vulnerability is disclosed.
