"""pymodbus framer/decoder harness (Atheris).

Server and client sides are selected by environment variable:
    PM_SIDE=server python harness_py.py ...   # DecodePDU(True)  = decode requests
    PM_SIDE=client python harness_py.py ...   # DecodePDU(False) = decode responses

Differences from the original harness:
  1. The protocol ID is no longer pinned to 0, so the claim that pymodbus
     rejects non-zero protocol IDs can actually be tested by fuzzing.
  2. The MBAP length field is deliberately skewed against the payload length.
     This is the control experiment for "pymodbus trusts the MBAP length
     field", and the direct counterpart of the req_length problem in libmodbus.
  3. There is an oracle. pymodbus swallows exceptions in a catch-all inside
     decoders.py, so without an oracle a result of zero crashes is guaranteed
     by construction rather than measured.
  4. An optional mode splits the input and feeds it to a single framer in
     sequence, which exercises buffer accumulation and resynchronisation.
"""
import os
import struct
import sys
import logging

import atheris

logging.disable(logging.CRITICAL)

with atheris.instrument_imports():
    from pymodbus.framer.socket import FramerSocket
    from pymodbus.framer.base import DecodePDU
    from pymodbus.exceptions import ModbusException

IS_SERVER = os.environ.get("PM_SIDE", "server") == "server"
decoder = DecodePDU(IS_SERVER)

# Rejections the specification allows. Anything else is reported as a finding.
EXPECTED_EXC = ()


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    proto_id = fdp.ConsumeUInt(2)                 # not pinned to zero
    len_delta = fdp.ConsumeIntInRange(-8, 8)      # skew the MBAP length field
    chunked = fdp.ConsumeBool()
    body = bytearray(fdp.ConsumeBytes(600))

    if len(body) < 8:
        return

    body[2] = (proto_id >> 8) & 0xFF
    body[3] = proto_id & 0xFF
    ln = max(0, min(0xFFFF, len(body) - 6 + len_delta))
    body[4] = (ln >> 8) & 0xFF
    body[5] = ln & 0xFF

    framer = FramerSocket(decoder)
    if chunked:
        chunks = [bytes(body[i:i + 7]) for i in range(0, len(body), 7)]
    else:
        chunks = [bytes(body)]

    try:
        for chunk in chunks:
            _used, _dev_id, _tid, pdu = framer.decode(chunk)
            if pdu:
                decoder.decode(pdu)
    except EXPECTED_EXC:
        # A legitimate rejection of a malformed frame, not a bug.
        pass
    except RecursionError:
        raise AssertionError("unbounded recursion in decode path")
    except MemoryError:
        raise AssertionError("attacker-controlled allocation in decode path")
    except (IndexError, struct.error, KeyError, AttributeError, TypeError,
            ValueError, OverflowError) as exc:
        # Internal parser state errors. This is the Python-side counterpart of
        # the memory-safety bug class in the C implementation.
        raise AssertionError(
            "unexpected %s from decode path: %s" % (type(exc).__name__, exc)
        )


atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
atheris.Fuzz()
