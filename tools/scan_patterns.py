"""R3nzSkin signature scanner.

Reimplements the exact search/resolve logic of R3nzSkin/memory.cpp against a
League of Legends.exe on disk, so we can tell which of the repo patterns still
match the live client build.

Usage:
    python tools/scan_patterns.py "<path to League of Legends.exe>"
"""
from __future__ import annotations

import struct
import sys


# (name, pattern-list, sub_base, read, relative, additional) -- mirrors Memory::sigs
GAME_CLIENT_SIGS = [
    ("global::GameClient", ["48 8B 05 ? ? ? ? 48 8B F2 83 78"], True, False, True, 0),
]

SIGS = [
    ("global::Player", ["48 8B 3D ? ? ? ? 48 85 FF 74 15 48 81 C7"], True, False, True, 0),
    ("global::ManagerTemplate_AIHero_", ["48 8B 05 ? ? ? ? 48 8B ? 08 8B 40 ? ? 8D ? ? ? 3B ? 74"], True, False, True, 0),
    ("global::ChampionManager", ["48 8B 0D ? ? ? ? 48 69 D0 ? ? 00 00 48 8B 05"], True, False, True, 0),
    ("global::ManagerTemplate_AIMinionClient_",
     ["48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? 48 8B 01"],
     True, False, True, 0),
    ("global::ManagerTemplate_AITurret_", ["48 8B 05 ? ? ? ? 48 8B ? 28 48 85 ? 74"], True, False, True, 0),
    ("global::Riot__g_window", ["48 8B 0D ? ? ? ? FF 15 ? ? ? ? 48 8B 05 ? ? ? ?"], True, False, True, 0),
    ("AIBaseCommon::CharacterDataStack", ["48 8D 8D ? ? 00 00 44 8B 8C 24 ? ? 00 00"], False, True, False, 0),
    ("AIBaseCommon::SkinId", ["88 86 ? ? 00 00 48 89 45 ? 0F B6 45 A8 88 86 ? 13"], False, True, False, 0),
    ("MaterialRegistry::SwapChain", ["48 8D BB ? ? ? ? C6 83 ? ? ? ? ? 0F 84"], False, True, False, 0),
    ("functions::CharacterDataStack__Push",
     ["E8 ? ? ? ? 48 8D 8D ? ? 00 00 E8 ? ? ? ? 48 85 C0 74 ? 48 85 ED"], True, False, False, 0),
    ("functions::CharacterDataStack__Update", ["88 54 24 10 55 53 56 57 41 54 41 55 41 56 41"], True, False, False, 0),
    ("functions::Riot__Renderer__MaterialRegistry__GetSingletonPtr", ["E8 ? ? ? ? 8B ? 34 45 33 C9"], True, False, False, 0),
    ("functions::translateString_UNSAFE_DONOTUSE", ["E8 ? ? ? ? 45 33 C0 48 8B D0 48 8B CB E8 ? ? ? ? E9"], True, False, False, 0),
    ("functions::GetGoldRedirectTarget", ["E8 ? ? ? ? 4C 3B ? 0F 94 C0"], True, False, False, 0),
]


class PE:
    def __init__(self, path: str):
        with open(path, "rb") as fh:
            self.data = fh.read()
        d = self.data
        self.e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if d[self.e_lfanew:self.e_lfanew + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        coff = self.e_lfanew + 4
        nsec, = struct.unpack_from("<H", d, coff + 2)
        opt_size, = struct.unpack_from("<H", d, coff + 16)
        opt = coff + 20
        magic, = struct.unpack_from("<H", d, opt)
        if magic == 0x10B:
            self.image_base, = struct.unpack_from("<I", d, opt + 28)
        elif magic == 0x20B:
            # PE32+: ImageBase is a ULONGLONG at optional-header offset 24
            self.image_base, = struct.unpack_from("<Q", d, opt + 24)
        else:
            raise ValueError(f"unknown optional header magic {magic:#x}")
        self.sections = []
        sec = opt + opt_size
        for i in range(nsec):
            off = sec + i * 40
            name = d[off:off + 8].rstrip(b"\0").decode("latin1")
            vsize, va, rawsize, raw = struct.unpack_from("<IIII", d, off + 8)
            self.sections.append({"name": name, "va": va, "vsize": vsize,
                                  "raw": raw, "rawsize": rawsize})
        # memory.cpp scans the first section only
        self.text = self.sections[0]

    def rva_to_off(self, rva: int):
        for s in self.sections:
            size = max(s["vsize"], s["rawsize"])
            if s["va"] <= rva < s["va"] + size:
                delta = rva - s["va"]
                if delta < s["rawsize"]:
                    return s["raw"] + delta
        return None

    def section_of(self, rva: int):
        for s in self.sections:
            size = max(s["vsize"], s["rawsize"])
            if s["va"] <= rva < s["va"] + size:
                return s["name"]
        return None

    def u32(self, rva: int):
        off = self.rva_to_off(rva)
        if off is None or off + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, off)[0]

    def u64(self, rva: int):
        off = self.rva_to_off(rva)
        if off is None or off + 8 > len(self.data):
            return None
        return struct.unpack_from("<Q", self.data, off)[0]


def pattern_to_bytes(pattern: str):
    out = []
    for tok in pattern.split():
        if tok.startswith("?"):
            out.append(-1)
        else:
            out.append(int(tok, 16))
    return out


def first_question_mark_index(pattern: str) -> int:
    idx = pattern.find("?")
    return idx


def find_all(pe: PE, pattern: str, limit: int = 50):
    """File-offset scan of the first section, mirroring find_signature()."""
    pb = pattern_to_bytes(pattern)
    s = len(pb)
    start = pe.text["raw"]
    buf = pe.data
    end = min(start + pe.text["rawsize"], len(buf))
    hits = []
    i = start
    while i < end - s:
        ok = True
        for j in range(s):
            if pb[j] != -1 and buf[i + j] != pb[j]:
                ok = False
                break
        if ok:
            hits.append(i - start + pe.text["va"])  # RVA
            if len(hits) >= limit:
                break
        i += 1
    return hits


def resolve(pe: PE, rva: int, sig):
    name, patterns, sub_base, read, relative, additional = sig
    address = rva
    if read:
        address = pe.u32(address + (first_question_mark_index(patterns[0]) // 3))
        if address is None:
            return None
    elif relative:
        disp = pe.u32(address + 3)
        if disp is None:
            return None
        if disp >= 0x80000000:
            disp -= 0x100000000
        address = address + disp + 7
    else:
        off = pe.rva_to_off(address)
        if off is None:
            return None
        if pe.data[off] == 0xE8:  # call rel32 -> follow it
            disp = pe.u32(address + 1)
            if disp is None:
                return None
            if disp >= 0x80000000:
                disp -= 0x100000000
            address = address + disp + 5
    # NOTE: memory.cpp works in absolute VA space and does `address -= base` when
    # sub_base is set, which yields an RVA. We already work in RVA space, so the
    # sub_base flag needs no adjustment here.
    address += additional
    return address


def main():
    path = sys.argv[1]
    pe = PE(path)
    print(f"file        : {path}")
    print(f"image base  : {pe.image_base:#x}")
    print(f"first sect  : {pe.text['name']} va={pe.text['va']:#x} rawsize={pe.text['rawsize']:#x}")
    print()

    for group, sigs in (("gameClientSig", GAME_CLIENT_SIGS), ("sigs", SIGS)):
        print(f"=== {group} ===")
        for sig in sigs:
            name, patterns, *_ = sig
            hits = find_all(pe, patterns[0])
            if not hits:
                print(f"  MISS      {name}")
                continue
            print(f"  HIT ({len(hits)}) {name}")
            for h in hits[:8]:
                r = resolve(pe, h, sig)
                if r is None:
                    print(f"        scan_rva={h:#010x} -> <unresolved>")
                    continue
                where = pe.section_of(r) or "?"
                print(f"        scan_rva={h:#010x} -> resolved={r:#010x} [{where}]")
        print()


if __name__ == "__main__":
    main()
