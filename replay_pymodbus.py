#!/usr/bin/env python3
"""replay_pymodbus.py — behavioral replay driver, not a fuzzer.

Reads one raw Modbus TCP ADU per invocation and classifies what
pymodbus did with it. Prints one TSV line:  <class>\t<detail>

Classes (chosen to line up with the libmodbus driver)
  ACCEPT      the PDU decoded into an object
  REJECT      the framer refused the frame outright
  DROP        the decoder's catch-all swallowed the fault, returned None
  INCOMPLETE  the framer is waiting for more bytes
  ERROR       an exception escaped to the caller

Distinguishing REJECT from INCOMPLETE is the whole reason this driver
captures log records. FramerSocket.decode() returns the same value --
(0, 0, 0, b"") -- on three different paths, and only the log says which
one was taken:

    len(data) < MIN_SIZE      Log.debug "Very short frame (NO MBAP)"
    protocol id != 0          Log.error "Invalid Modbus protocol id"
    len(data) < declared len  Log.debug "Short frame: ... wait for more data"

The first and third are waits; the second is a refusal. We key on the
severity pymodbus itself assigned (ERROR vs DEBUG) rather than on
matching its message text, so the mapping does not depend on our
reading of the wording. Log.setLevel(DEBUG) is required or the two
DEBUG paths emit nothing and both collapse into "no log record".

Takes raw ADUs, not FuzzedDataProvider input, so that both drivers can
be handed byte-identical files.

    PM_SIDE=server python3 replay_pymodbus.py <adu-file>
"""
import logging
import os
import sys

from pymodbus.framer.socket import FramerSocket
from pymodbus.framer.base import DecodePDU
from pymodbus.logging import Log

RECORDS = []          # list of (levelno, message)


class _Capture(logging.Handler):
    def emit(self, record):
        try:
            RECORDS.append((record.levelno, record.getMessage()))
        except Exception:
            pass


def _install_capture():
    handler = _Capture()
    for name in ("", "pymodbus", "pymodbus.logging"):
        log = logging.getLogger(name)
        log.addHandler(handler)
        log.setLevel(logging.DEBUG)
        log.propagate = True
    # Log guards every call with isEnabledFor(); without this the DEBUG
    # "wait for more data" paths are silent.
    Log.setLevel(logging.DEBUG)


def _worst():
    """Highest-severity captured record, as (levelno, message)."""
    worst = max(lvl for lvl, _ in RECORDS)
    return worst, next(msg for lvl, msg in RECORDS if lvl == worst)


def classify(data):
    decoder = DecodePDU(os.environ.get("PM_SIDE", "server") == "server")
    framer = FramerSocket(decoder)

    try:
        used, _dev_id, _tid, pdu = framer.decode(data)
    except Exception as exc:                       # noqa: BLE001
        return "ERROR", f"{type(exc).__name__} from framer: {exc}"

    if not pdu:
        # All three bail-out paths above return used == 0, which is
        # pymodbus's own "I did not consume this, send more" signal. A
        # nonzero used with an empty PDU is a fourth path: a declared
        # length of 0 makes msg_len 6, so data[7:6] is empty. The framer
        # reports 6 bytes consumed and hands the caller nothing, with no
        # exception and no log line -- on a live stream that advances the
        # buffer past a frame boundary.
        if used:
            return "DROP", f"framer consumed {used} bytes, returned empty PDU"
        if not RECORDS:
            return "INCOMPLETE", "framer consumed 0 bytes, no log record"
        level, msg = _worst()
        if level >= logging.ERROR:
            return "REJECT", f"framer: {msg}"
        return "INCOMPLETE", f"framer waiting: {msg}"

    try:
        obj = decoder.decode(pdu)
    except Exception as exc:                       # noqa: BLE001
        return "ERROR", f"{type(exc).__name__} from decoder: {exc}"

    if obj is None:
        detail = RECORDS[-1][1] if RECORDS else "no log record"
        return "DROP", f"decoder returned None: {detail}"

    return "ACCEPT", type(obj).__name__


def main():
    if len(sys.argv) != 2:
        print("usage: replay_pymodbus.py <adu-file>", file=sys.stderr)
        return 2

    _install_capture()

    with open(sys.argv[1], "rb") as fh:
        data = fh.read()

    if not data:
        print("SKIP\tempty file")
        return 0

    cls, detail = classify(data)
    print(f"{cls}\t{detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
