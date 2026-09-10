"""In-place signature-string patcher for a prebuilt R3nzSkin.dll.

The patterns in memory.hpp are plain ASCII string literals baked into .rdata, so a
released DLL can be re-pointed at a new client build without recompiling -- as long
as the replacement string is not longer than the original one.

Padding rule matters: Memory::Search parses the string token by token, and a bare
unparseable character would be turned into a spurious 0x00 byte. So the slack is
filled with wildcard tokens ("? " repeated, plus a trailing "?" when the slack is
odd), which keeps the pattern semantically identical and only makes it longer.

Usage:
    python tools/patch_dll_strings.py <dll>            # dry run / inspect
    python tools/patch_dll_strings.py <dll> --apply    # write <dll>.patched.dll
"""
from __future__ import annotations

import sys

OLD_MINION = ("48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ? "
              "48 8B 0D ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? 48 8B 01")
NEW_MINION = "48 8B 0D ? ? ? ? 8B D2 E8 ? ? ? ? 48 8B 0D ? ? ? ? 33 D2 48 83 C4 28 E9"

OLD_TS = "E8 ? ? ? ? 45 33 C0 48 8B D0 48 8B CB E8 ? ? ? ? E9"
NEW_TS = "40 53 48 83 EC 30 80 39 00 48 8B C1 8B D1 74 0B"

REPLACEMENTS = [
    ("ManagerTemplate_AIMinionClient_", OLD_MINION, NEW_MINION),
    ("translateString_UNSAFE_DONOTUSE", OLD_TS, NEW_TS),
]


def build_padded(new: str, old: str) -> str:
    """Return `new` padded with wildcard tokens to exactly len(old) characters."""
    slack = len(old) - len(new)
    if slack < 0:
        raise ValueError(f"replacement longer than original ({len(new)} > {len(old)})")
    pad = "? " * (slack // 2)
    if slack % 2:
        pad += "?"
    out = new + pad
    assert len(out) == len(old), (len(out), len(old))
    return out


def count_byte_tokens(pattern: str) -> int:
    """Mirror pattern_to_byte(): how many bytes this string decodes to."""
    n = 0
    i = 0
    while i < len(pattern):
        if pattern[i] == "?":
            i += 1
            if i < len(pattern) and pattern[i] == "?":
                i += 1
            n += 1
        elif pattern[i] == " ":
            i += 1
        else:
            while i < len(pattern) and pattern[i] != " " and pattern[i] != "?":
                i += 1
            n += 1
    return n


def main():
    dll = sys.argv[1]
    apply_ = "--apply" in sys.argv
    data = bytearray(open(dll, "rb").read())
    print(f"dll    : {dll}")
    print(f"size   : {len(data):,} bytes\n")

    # are the strings plaintext at all?
    for name, old, new in REPLACEMENTS:
        needle = old.encode("ascii")
        hits = []
        start = 0
        while True:
            i = bytes(data).find(needle, start)
            if i < 0:
                break
            hits.append(i)
            start = i + 1
        print(f"[{name}]")
        print(f"  original string ({len(old)} chars) found at: "
              f"{[hex(h) for h in hits] if hits else 'NOT FOUND -> DLL is packed/encrypted'}")
        if not hits:
            continue
        padded = build_padded(new, old)
        print(f"  new string      ({len(new)} chars) + {len(old) - len(new)} chars wildcard padding")
        print(f"  decoded bytes   : {count_byte_tokens(old)} -> {count_byte_tokens(padded)}")
        print(f"  tokens          : {padded}")
        if len(hits) > 1:
            print("  !! more than one occurrence -- refusing to patch automatically")
            continue
        if apply_:
            data[hits[0]:hits[0] + len(old)] = padded.encode("ascii")
            print("  patched")
    print()

    if apply_:
        out = dll.rsplit(".", 1)[0] + ".patched.dll"
        open(out, "wb").write(bytes(data))
        print(f"wrote {out}")
    else:
        print("dry run only -- re-run with --apply to write <dll>.patched.dll")


if __name__ == "__main__":
    main()
