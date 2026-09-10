"""Parse R3nzSkin/memory.hpp signatures straight out of the C++ source and scan a
League of Legends.exe with them -- the exact logic of Memory::Search().

Usage:
    python tools/verify_memory_hpp.py <exe> [path-to-memory.hpp]
"""
from __future__ import annotations

import re
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from scan_patterns import PE, find_all, resolve  # noqa: E402

DEFAULT_HPP = r"D:\Learn\projects\Githubs\R3nzSkin\R3nzSkin\memory.hpp"

# { { "PAT" }, sub_base, read, relative, additional, &offsets::xxx }
# (a `//` comment line may sit between `{ {` and the pattern string)
SIG_RE = re.compile(
    r'\{\s*\{\s*(?://[^\n]*\n\s*)*"([^"]+)"\s*(?:,\s*"([^"]+)")?\s*\}\s*,\s*'
    r'(true|false)\s*,\s*(true|false)\s*,\s*(true|false)\s*,\s*(-?\d+)\s*,\s*&([\w:]+)',
    re.S,
)


def parse(hpp_path: str):
    text = open(hpp_path, encoding="utf-8", errors="replace").read()
    out = []
    for m in SIG_RE.finditer(text):
        pats = [m.group(1)] + ([m.group(2)] if m.group(2) else [])
        out.append((m.group(7), pats,
                    m.group(3) == "true", m.group(4) == "true",
                    m.group(5) == "true", int(m.group(6))))
    return out


def main():
    exe = sys.argv[1]
    hpp = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HPP
    pe = PE(exe)
    sigs = parse(hpp)
    print(f"exe     : {exe}")
    print(f"memory  : {hpp}")
    print(f"{len(sigs)} signatures parsed\n")

    ok = miss = 0
    for name, pats, sub_base, read, relative, additional in sigs:
        found = None
        for p in pats:
            hits = find_all(pe, p, 4)
            if hits:
                found = (p, hits[0])
                break
        if not found:
            miss += 1
            print(f"  MISS  {name}")
            continue
        ok += 1
        p, hit = found
        r = resolve(pe, hit, (name, pats, sub_base, read, relative, additional))
        print(f"  OK    {name:<58} scan={hit:#010x} -> {r:#010x}")
    print(f"\nresult: {ok} ok / {miss} miss")
    return 1 if miss else 0


if __name__ == "__main__":
    raise SystemExit(main())
