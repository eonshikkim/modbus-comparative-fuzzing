# Same Specification, Different Attack Surface

Comparative fuzzing of two independent Modbus TCP server implementations:
**libmodbus** (C) and **pymodbus** (Python). Both implement the same
public specification, so differences in what they accept, reject, or
crash on come from the implementations rather than from the protocol.


## Results

**CVE-2024-10918 reproduced and minimized.** `modbus_reply` in libmodbus
v3.1.10 copies `req_length` bytes into `uint8_t rsp[260]` with no check
that the two agree. The minimized proof-of-concept is 261 bytes, one
past `MAX_MESSAGE_LENGTH`. Fixed in v3.1.11 by
`compute_response_length_from_request`.

**The same defect is reachable at three sites, not one.** v3.1.10 has
the identical unvalidated `memcpy(rsp, req, req_length)` in three
`case` branches — `modbus.c:905` (FC 0x05), `:936` (FC 0x06) and
`:1058` (FC 0x16). The CVE write-up cites only the first. A 300k-exec
campaign reached 0x16; a 30-minute campaign reached all three. 0x05 is
the narrowest gate, requiring the data field to equal `0xFF00` or
`0x0000`, and was still reached twice.

**The threat model decides reachability, not the code.** Under a
260-byte bound on `req_length` — what `_modbus_receive_msg` can
actually deliver over the network — the same library, the same input
and the same build produce no crash in 29,377,732 executions. Under a
1024-byte bound, modeling a caller that supplies its own length, the
crash is immediate. Reporting "vulnerable" without naming the bound
says very little.

**pymodbus crash counts are N/A, not 0.** The catch-all at
`pdu/decoders.py:93` converts `struct.error`, `IndexError`,
`ValueError` and `ModbusException` into a log line and a `None`
return. Exception-based oracles are structurally unable to observe
parser faults at that layer. Removing the exception whitelist entirely
produced no uncaught exception in 5,000 executions.

**Shared-input replay.** 27 raw ADUs replayed against six
configurations; 17 diverge. libmodbus never consults the MBAP length
field and accepts every frame that lies about it. pymodbus does
consult it, but a frame declaring more bytes than arrived makes the
framer wait for data that cannot come rather than rejecting it — the
same unverified field causes over-acceptance in one library and loss
of progress in the other. The protocol ID is the only frame-level
check pymodbus refuses outright. On PDU contents the usual narrative
inverts: libmodbus answers every malformed-PDU probe with an exception
response, while pymodbus accepts some of them and its client and
server paths disagree on three.

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
  the harness. Stack redzones are placed at compile time. The same
  harness ran 630,698 executions without a crash against an
  uninstrumented build and crashed within seconds against an
  instrumented one.
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
