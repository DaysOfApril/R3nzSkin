"""Report the PE facts that matter for injection: machine type, DLL flag, entry
point, TLS, imports and exports.

Usage:
    python tools/pe_report.py <file> [more files...]
"""
from __future__ import annotations

import struct
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from scan_patterns import PE  # noqa: E402

MACHINE = {0x14C: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0xAA64: "arm64"}
SUBSYSTEM = {2: "GUI", 3: "CONSOLE"}


class PE2(PE):
    def __init__(self, path):
        super().__init__(path)
        d = self.data
        coff = self.e_lfanew + 4
        self.machine, self.nsec, = struct.unpack_from("<HH", d, coff)
        self.characteristics, = struct.unpack_from("<H", d, coff + 18)
        opt = coff + 20
        self.opt = opt
        magic, = struct.unpack_from("<H", d, opt)
        self.plus = magic == 0x20B
        self.entry, = struct.unpack_from("<I", d, opt + 16)
        self.subsystem, = struct.unpack_from("<H", d, opt + (68 if self.plus else 68))
        self.dd_off = opt + (112 if self.plus else 96)
        n, = struct.unpack_from("<I", d, opt + (108 if self.plus else 92))
        self.dirs = []
        for i in range(min(n, 16)):
            rva, size = struct.unpack_from("<II", d, self.dd_off + i * 8)
            self.dirs.append((rva, size))

    def dir(self, i):
        return self.dirs[i] if i < len(self.dirs) else (0, 0)

    def cstr(self, rva):
        off = self.rva_to_off(rva)
        if off is None:
            return None
        end = self.data.find(b"\0", off)
        return self.data[off:end].decode("latin1", "replace")

    def imports(self):
        rva, _ = self.dir(1)
        out = []
        if not rva:
            return out
        off = self.rva_to_off(rva)
        if off is None:
            return out
        while True:
            oft, tds, fwd, name, ft = struct.unpack_from("<IIIII", self.data, off)
            if not any((oft, tds, fwd, name, ft)):
                break
            dll = self.cstr(name)
            thunk_rva = oft or ft
            funcs = []
            toff = self.rva_to_off(thunk_rva)
            step = 8 if self.plus else 4
            if toff is not None:
                i = 0
                while True:
                    val = struct.unpack_from("<Q" if self.plus else "<I",
                                             self.data, toff + i * step)[0]
                    if val == 0:
                        break
                    high = 1 << (63 if self.plus else 31)
                    if val & high:
                        funcs.append(f"#{val & 0xFFFF}")
                    else:
                        nm = self.cstr((val & 0x7FFFFFFF) + 2)
                        funcs.append(nm or "?")
                    i += 1
                    if i > 400:
                        funcs.append("...")
                        break
            out.append((dll, funcs))
            off += 20
        return out

    def exports(self):
        rva, size = self.dir(0)
        if not rva or not size:
            return None, []
        off = self.rva_to_off(rva)
        if off is None:
            return None, []
        (chars, tds, major, minor, name_rva, base, nfunc,
         nnames, addr_funcs, addr_names, addr_ords) = struct.unpack_from(
            "<IIHHIIIIIII", self.data, off)
        dll_name = self.cstr(name_rva)
        names = []
        noff = self.rva_to_off(addr_names)
        ooff = self.rva_to_off(addr_ords)
        foff = self.rva_to_off(addr_funcs)
        for i in range(min(nnames, 50)):
            nrva, = struct.unpack_from("<I", self.data, noff + i * 4)
            ordv, = struct.unpack_from("<H", self.data, ooff + i * 2)
            frva, = struct.unpack_from("<I", self.data, foff + ordv * 4)
            names.append((self.cstr(nrva), frva))
        return dll_name, names


def main():
    for path in sys.argv[1:]:
        pe = PE2(path)
        print("=" * 78)
        print(f"{path}")
        print(f"  size          : {len(pe.data):,} bytes")
        print(f"  machine       : {MACHINE.get(pe.machine, hex(pe.machine))}")
        print(f"  characteristics: {pe.characteristics:#06x} "
              f"({'DLL' if pe.characteristics & 0x2000 else 'EXE'}"
              f"{', RELOCS_STRIPPED' if pe.characteristics & 1 else ''})")
        print(f"  subsystem     : {SUBSYSTEM.get(pe.subsystem, pe.subsystem)}")
        print(f"  image base    : {pe.image_base:#x}")
        print(f"  entry point   : {pe.entry:#x}")
        print(f"  sections      : {[s['name'] for s in pe.sections]}")
        tls_rva, tls_size = pe.dir(9)
        print(f"  TLS directory : {tls_rva:#x} (size {tls_size})")
        com_rva, com_size = pe.dir(14)
        print(f"  CLR (.NET)    : {com_rva:#x} (size {com_size})")

        dll_name, exps = pe.exports()
        print(f"  exports       : {len(exps)} (module name: {dll_name})")
        for nm, rva in exps:
            print(f"      {nm} @ {rva:#x}")

        print(f"  imports       :")
        for dll, funcs in pe.imports():
            shown = ", ".join(funcs[:12])
            more = f", ...(+{len(funcs) - 12})" if len(funcs) > 12 else ""
            print(f"      {dll}: {shown}{more}")
        print()


if __name__ == "__main__":
    main()
