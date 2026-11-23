"""Synthetic PE images for header-hardening tests. Never executed."""
import struct

DLL_GUARD_CF = 0x4000


def synthetic_pe(dll=0x8160, characteristics=0x22, reloc=(0x3000, 12), cert=0, text=0x60000020,
                 entry=0x1010, wide=True, guard=False):
    """A minimal PE with one .text section; `guard` adds GUARD_CF and a load-config directory."""
    optional_size = 240 if wide else 224
    table = 64 + 24 + optional_size
    raw = 0x200
    data = bytearray(raw + 0x200 + cert)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, 64)
    data[64:68] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 68, 0x8664 if wide else 0x14C, 1, 0, 0, 0, optional_size, characteristics)
    opt = 88
    struct.pack_into('<H', data, opt, 0x20B if wide else 0x10B)
    struct.pack_into('<I', data, opt + 16, entry)
    struct.pack_into('<H', data, opt + 70, dll | (DLL_GUARD_CF if guard else 0))
    directories = opt + (112 if wide else 96)
    struct.pack_into('<I', data, directories - 4, 16)
    struct.pack_into('<II', data, directories + 8 * 5, *reloc)
    if guard:
        struct.pack_into('<II', data, directories + 8 * 10, 0x1100, 320)
    if cert:
        struct.pack_into('<II', data, directories + 8 * 4, raw + 0x200, cert)
    struct.pack_into('<8sIIII', data, table, b'.text', 0x200, 0x1000, 0x200, raw)
    struct.pack_into('<I', data, table + 36, text)
    return data
