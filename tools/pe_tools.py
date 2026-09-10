"""Helpers for porting R3nzSkin signatures to a new client build.

Subcommands:
    refs  <exe> <global_rva>          find `mov reg,[rip+disp]` loads of a global
    dump  <exe> <rva> <len>           hex dump
    ptr   <exe> <rva> [count]         dump qword values (follow global slots)
    find  <exe> "<pattern>" [limit]   wildcard search in .text
"""
from __future__ import annotations

import struct
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from scan_patterns import PE, find_all, pattern_to_bytes  # noqa: E402

# `mov r64, [rip+disp32]` opcodes we care about
RIP_LOADS = {
    0x05: "rax", 0x0D: "rcx", 0x15: "rdx", 0x1D: "rbx",
    0x25: "rsp", 0x2D: "rbp", 0x35: "rsi", 0x3D: "rdi",
}


def signed32(v: int) -> int:
    return v - 0x100000000 if v >= 0x80000000 else v


def scan_rip_loads(pe: PE, targets: set[int]):
    """Return {target: [(rva, reg)]} for every RIP-relative mov into a register."""
    out: dict[int, list[tuple[int, str]]] = {t: [] for t in targets}
    sect = pe.text
    start = sect["raw"]
    end = min(start + sect["rawsize"], len(pe.data)) - 7
    buf = pe.data
    va = sect["va"]
    i = start
    while i < end:
        b0 = buf[i]
        if b0 == 0x48 or b0 == 0x4C:
            b1 = buf[i + 1]
            b2 = buf[i + 2]
            if b1 == 0x8B and b2 in RIP_LOADS:
                disp = struct.unpack_from("<i", buf, i + 3)[0]
                rva = i - start + va
                tgt = rva + 7 + disp
                if tgt in out:
                    out[tgt].append((rva, ("r" if b0 == 0x4C else "") + RIP_LOADS[b2]))
                i += 7
                continue
        i += 1
    return out


def hexdump(pe: PE, rva: int, length: int):
    off = pe.rva_to_off(rva)
    if off is None:
        print("  <rva not mapped>")
        return
    d = pe.data[off:off + length]
    for row in range(0, len(d), 16):
        chunk = d[row:row + 16]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {rva + row:#010x}  {hexpart:<47}  {text}")


def main():
    cmd = sys.argv[1]
    path = sys.argv[2]
    pe = PE(path)
    print(f"file: {path}")
    print(f"version: {pe.sections and ''}{getattr(pe, 'version', 'n/a')}")

    if cmd == "sections":
        for s in pe.sections:
            print(f"  {s['name']:<9} va={s['va']:#010x} vsize={s['vsize']:#010x} "
                  f"raw={s['raw']:#010x} rawsize={s['rawsize']:#010x}")
    elif cmd == "refs":
        targets = {int(a, 16) for a in sys.argv[3:]}
        res = scan_rip_loads(pe, targets)
        for t, refs in res.items():
            print(f"\nglobal {t:#010x}  ->  {len(refs)} reference(s)")
            for rva, reg in refs[:40]:
                print(f"    {rva:#010x}  mov {reg}, [rip+..]")
    elif cmd == "dump":
        hexdump(pe, int(sys.argv[3], 16), int(sys.argv[4], 10))
    elif cmd == "ptr":
        rva = int(sys.argv[3], 16)
        count = int(sys.argv[4], 10) if len(sys.argv) > 4 else 1
        for i in range(count):
            v = pe.u64(rva + i * 8)
            print(f"  [{rva + i * 8:#010x}] = {v:#018x}" if v is not None else "  <unmapped>")
    elif cmd == "find":
        pat = sys.argv[3]
        limit = int(sys.argv[4], 10) if len(sys.argv) > 4 else 20
        hits = find_all(pe, pat, limit)
        print(f"pattern: {pat}")
        print(f"hits: {len(hits)}")
        for h in hits:
            print(f"    {h:#010x}")
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
