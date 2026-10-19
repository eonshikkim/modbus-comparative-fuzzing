#!/usr/bin/env python3
"""Shared input set for the cross-implementation replay.

Every file here is a RAW Modbus TCP ADU. Both replay drivers read these
bytes directly, with no harness-specific wrapper, so the two libraries
genuinely receive the same input. This is why the replay drivers do not
reuse the fuzzing harnesses: the Atheris harness consumes its first
bytes through FuzzedDataProvider, which would make "the same file" mean
different things to each side.

Groups:
  valid/   well-formed requests, one per function code
  probe/   one targeted probe per row of the static divergence table
  poc/     the minimized CVE-2024-10918 input, if present
"""
import pathlib
import shutil

H = bytes.fromhex


def mbap(tid, pdu, unit=0xFF, proto=0x0000, length=None):
    """MBAP header + PDU. length defaults to the correct value."""
    body = bytes([unit]) + pdu
    if length is None:
        length = len(body)
    return (tid.to_bytes(2, "big") + proto.to_bytes(2, "big")
            + length.to_bytes(2, "big") + body)


VALID = {
    "fc01_read_coils":     H("01") + H("0000") + H("0008"),
    "fc02_read_discrete":  H("02") + H("0000") + H("0008"),
    "fc03_read_holding":   H("03") + H("0000") + H("000a"),
    "fc04_read_input":     H("04") + H("0000") + H("000a"),
    "fc05_write_coil":     H("05") + H("0010") + H("ff00"),
    "fc06_write_reg":      H("06") + H("0010") + H("1234"),
    "fc0f_write_coils":    H("0f") + H("0000") + H("0008") + H("01") + H("cd"),
    "fc10_write_regs":     H("10") + H("0000") + H("0002") + H("04")
                           + H("00010002"),
    "fc16_mask_write":     H("16") + H("0004") + H("00f2") + H("0025"),
}

# One probe per row of the divergence table, so the behavioral result
# can be read against the static mapping line by line.
BASE = H("03") + H("0000") + H("000a")          # a valid read-holding PDU


def build_probes():
    p = {}

    # Row: protocol ID must be 0
    p["pid_nonzero"] = mbap(1, BASE, proto=0x0001)
    p["pid_garbage"] = mbap(2, BASE, proto=0x3030)

    # Row: MBAP length field
    p["len_too_large"] = mbap(3, BASE, length=0x00FF)
    p["len_too_small"] = mbap(4, BASE, length=0x0002)
    p["len_zero"]      = mbap(5, BASE, length=0x0000)
    p["len_max"]       = mbap(6, BASE, length=0xFFFF)

    # Row: truncated ADU
    p["trunc_4bytes"] = mbap(7, BASE)[:4]
    p["trunc_7bytes"] = mbap(8, BASE)[:7]
    p["trunc_mid_pdu"] = mbap(9, BASE)[:9]

    # Row: unknown function code
    p["fc_unknown_7f"] = mbap(10, H("7f") + H("0000") + H("0008"))
    p["fc_unknown_00"] = mbap(11, H("00") + H("0000") + H("0008"))
    p["fc_exception_bit"] = mbap(12, H("83") + H("02"))

    # Row: malformed PDU payload
    p["pdu_bytecount_lies"] = mbap(
        13, H("10") + H("0000") + H("0002") + H("ff") + H("00010002"))
    p["pdu_quantity_huge"] = mbap(14, H("03") + H("0000") + H("ffff"))
    p["pdu_quantity_zero"] = mbap(15, H("03") + H("0000") + H("0000"))
    p["pdu_addr_out_of_range"] = mbap(16, H("03") + H("ffff") + H("000a"))

    # Combination: what the minimized PoC actually carries
    p["combo_pid_and_len"] = mbap(17, BASE, proto=0x3030, length=0x3030)

    return p


def main():
    root = pathlib.Path("replay_inputs")
    if root.exists():
        shutil.rmtree(root)
    for sub in ("valid", "probe", "poc"):
        (root / sub).mkdir(parents=True)

    for tid, (name, pdu) in enumerate(VALID.items(), start=100):
        (root / "valid" / f"{name}.bin").write_bytes(mbap(tid, pdu))

    for name, blob in build_probes().items():
        (root / "probe" / f"{name}.bin").write_bytes(blob)

    poc = pathlib.Path("min.bin")
    if poc.exists():
        shutil.copy(poc, root / "poc" / "cve_2024_10918.bin")
        print("poc/      1 file (min.bin)")
    else:
        print("poc/      0 files (min.bin not found in cwd; copy it in "
              "to include the CVE input)")

    print(f"valid/    {len(VALID)} files")
    print(f"probe/    {len(build_probes())} files")


if __name__ == "__main__":
    main()
