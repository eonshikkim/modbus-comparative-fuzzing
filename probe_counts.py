import glob, collections
import atheris
from pymodbus.framer.socket import FramerSocket
from pymodbus.framer.base import DecodePDU

decoder = DecodePDU(True)
stats = collections.Counter()
excs = collections.Counter()

files = sorted(glob.glob("corpus_py_srv_t1/*") + glob.glob("seeds_py/*"))
for path in files:
    data = open(path, "rb").read()
    fdp = atheris.FuzzedDataProvider(data)
    proto_id = fdp.ConsumeUInt(2)
    len_delta = fdp.ConsumeIntInRange(-8, 8)
    fdp.ConsumeBool()
    body = bytearray(fdp.ConsumeBytes(600))
    if len(body) < 8:
        stats["skipped_too_short"] += 1
        continue
    body[2] = (proto_id >> 8) & 0xFF
    body[3] = proto_id & 0xFF
    ln = max(0, min(0xFFFF, len(body) - 6 + len_delta))
    body[4] = (ln >> 8) & 0xFF
    body[5] = ln & 0xFF
    stats["reached_framer"] += 1
    try:
        used, dev, tid, pdu = framer_out = FramerSocket(decoder).decode(bytes(body))
        if pdu:
            stats["framer_returned_pdu"] += 1
            obj = decoder.decode(pdu)
            stats["decode_none" if obj is None else "decode_object"] += 1
        else:
            stats["framer_no_pdu"] += 1
    except BaseException as e:
        excs[type(e).__name__] += 1

print("files:", len(files))
for k, v in stats.most_common():
    print(f"  {k}: {v}")
print("exceptions:", dict(excs) or "none")
