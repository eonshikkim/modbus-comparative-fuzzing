#!/usr/bin/env python3
"""Seed corpus generator for the AFL++ and Atheris campaigns.

seeds/        server harness — valid Modbus TCP request ADUs
seeds_client/ client harness — [op][nb] prefix + valid response ADUs
"""
import pathlib

H = bytes.fromhex


def mbap(tid, pdu, unit=0xFF):
    """MBAP header + PDU. Length covers the unit id byte plus the PDU."""
    body = bytes([unit]) + pdu
    return tid.to_bytes(2, "big") + b"\x00\x00" + len(body).to_bytes(2, "big") + body


# ---- server side: requests ----------------------------------------------
requests = {
    "fc01_read_coils":      H("01") + H("0000") + H("0008"),
    "fc02_read_discrete":   H("02") + H("0000") + H("0008"),
    "fc03_read_holding":    H("03") + H("0000") + H("000a"),
    "fc04_read_input":      H("04") + H("0000") + H("000a"),
    "fc05_write_coil_on":   H("05") + H("0010") + H("ff00"),
    "fc05_write_coil_off":  H("05") + H("0010") + H("0000"),
    "fc06_write_reg":       H("06") + H("0010") + H("1234"),
    "fc0f_write_coils":     H("0f") + H("0000") + H("0008") + H("01") + H("cd"),
    "fc10_write_regs":      H("10") + H("0000") + H("0002") + H("04") + H("00010002"),
    "fc11_report_id":       H("11"),
    "fc16_mask_write":      H("16") + H("0004") + H("00f2") + H("0025"),
    "fc17_rw_regs":         H("17") + H("0003") + H("0006") + H("000e") + H("0003")
                            + H("06") + H("00ff00ff00ff"),
    "fc2b_encap":           H("2b") + H("0e") + H("01") + H("00"),
}

# ---- client side: [op][nb] + response ------------------------------------
# op values follow the switch order in harness_client.c.
responses = {
    "op0_fc01_rsp": bytes([0, 8]) + mbap(1, H("01") + H("01") + H("cd")),
    "op1_fc02_rsp": bytes([1, 8]) + mbap(1, H("02") + H("01") + H("cd")),
    "op2_fc03_rsp": bytes([2, 2]) + mbap(1, H("03") + H("04") + H("00010002")),
    "op3_fc04_rsp": bytes([3, 2]) + mbap(1, H("04") + H("04") + H("00010002")),
    "op4_fc05_rsp": bytes([4, 1]) + mbap(1, H("05") + H("0000") + H("ff00")),
    "op5_fc06_rsp": bytes([5, 1]) + mbap(1, H("06") + H("0000") + H("1234")),
    "op6_fc0f_rsp": bytes([6, 8]) + mbap(1, H("0f") + H("0000") + H("0008")),
    "op7_fc10_rsp": bytes([7, 2]) + mbap(1, H("10") + H("0000") + H("0002")),
    "op8_fc17_rsp": bytes([8, 3]) + mbap(1, H("17") + H("06") + H("00ff00ff00ff")),
    "op0_exception": bytes([0, 8]) + mbap(1, H("81") + H("02")),
    "op2_exception": bytes([2, 2]) + mbap(1, H("83") + H("02")),
}


def main():
    srv = pathlib.Path("seeds")
    cli = pathlib.Path("seeds_client")
    srv.mkdir(exist_ok=True)
    cli.mkdir(exist_ok=True)

    for tid, (name, pdu) in enumerate(requests.items(), start=1):
        (srv / f"{name}.bin").write_bytes(mbap(tid, pdu))

    for name, blob in responses.items():
        (cli / f"{name}.bin").write_bytes(blob)

    print(f"seeds/        {len(requests)} files")
    print(f"seeds_client/ {len(responses)} files")


if __name__ == "__main__":
    main()
