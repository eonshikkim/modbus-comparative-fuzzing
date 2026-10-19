#!/usr/bin/env python3
"""Seed corpus for the Atheris harnesses.

harness_py.py reads its first few bytes through FuzzedDataProvider (protocol
id, length delta, chunked flag) and treats the remainder as the frame. Feeding
it the raw ADUs from mkseeds.py therefore produces frames that do not parse,
which handicaps the pymodbus side of the comparison.

This writes the same ADUs with a control prefix in front so the seeds start as
well-formed frames: protocol id 0, length delta 0, chunked off.

The exact number of prefix bytes FuzzedDataProvider consumes is an
implementation detail, so this is a warm start rather than an exact encoding.
Coverage-guided mutation corrects any offset within the first few hundred runs.
"""
import pathlib

H = bytes.fromhex
PREFIX = bytes([0x00, 0x00, 0x08, 0x00])   # proto id 0, len_delta 0, chunked off


def mbap(tid, pdu, unit=0xFF):
    body = bytes([unit]) + pdu
    return tid.to_bytes(2, "big") + b"\x00\x00" + len(body).to_bytes(2, "big") + body


requests = {
    "fc01_read_coils":     H("01") + H("0000") + H("0008"),
    "fc02_read_discrete":  H("02") + H("0000") + H("0008"),
    "fc03_read_holding":   H("03") + H("0000") + H("000a"),
    "fc04_read_input":     H("04") + H("0000") + H("000a"),
    "fc05_write_coil":     H("05") + H("0010") + H("ff00"),
    "fc06_write_reg":      H("06") + H("0010") + H("1234"),
    "fc0f_write_coils":    H("0f") + H("0000") + H("0008") + H("01") + H("cd"),
    "fc10_write_regs":     H("10") + H("0000") + H("0002") + H("04") + H("00010002"),
    "fc11_report_id":      H("11"),
    "fc16_mask_write":     H("16") + H("0004") + H("00f2") + H("0025"),
    "fc17_rw_regs":        H("17") + H("0003") + H("0006") + H("000e") + H("0003")
                           + H("06") + H("00ff00ff00ff"),
    "fc2b_encap":          H("2b") + H("0e") + H("01") + H("00"),
}

responses = {
    "rsp_fc01": H("01") + H("01") + H("cd"),
    "rsp_fc03": H("03") + H("04") + H("00010002"),
    "rsp_fc10": H("10") + H("0000") + H("0002"),
    "rsp_exception": H("83") + H("02"),
}


def main():
    out = pathlib.Path("seeds_py")
    out.mkdir(exist_ok=True)

    n = 0
    for tid, (name, pdu) in enumerate(requests.items(), start=1):
        (out / f"req_{name}.bin").write_bytes(PREFIX + mbap(tid, pdu))
        n += 1
    for tid, (name, pdu) in enumerate(responses.items(), start=100):
        (out / f"{name}.bin").write_bytes(PREFIX + mbap(tid, pdu))
        n += 1

    # A few oversized frames so libFuzzer raises its length limit early.
    (out / "long_fc03.bin").write_bytes(
        PREFIX + mbap(200, H("03") + H("0000") + H("000a")) + b"A" * 300)
    (out / "long_fc10.bin").write_bytes(
        PREFIX + mbap(201, H("10") + H("0000") + H("0002") + H("04") + H("00010002")) + b"A" * 300)
    n += 2

    print(f"seeds_py/ {n} files")


if __name__ == "__main__":
    main()
