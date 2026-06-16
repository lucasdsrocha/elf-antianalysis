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
    EHDR_SIZE, PHDR_SIZE,
    Elf64_Ehdr, Elf64_Phdr,
    ElfFile, ElfType, PType,
)

log = logging.getLogger('patcher_newseg')

PAGE_SIZE = 0x1000

# Segment permission flags (p_flags)
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

# Maximum reach of a signed 32-bit RIP-relative displacement.
RIP_REL_MAX = 2**31


# Helpers (identical to patcher_ptnote.py)
def _align_up(value: int, alignment: int) -> int:
    """Round `value` up to the next multiple of `alignment`."""
    return (value + alignment - 1) & ~(alignment - 1)


def _max_vaddr(elf: ElfFile) -> int:
    """Highest virtual address occupied by PT_LOAD segments."""
    return max(
        (seg.header.p_vaddr + seg.header.p_memsz
         for seg in elf.segments
         if seg.header.p_type == PType.LOAD),
        default=0,
    )


# Register-preserving boilerplate (save all GPRs before payload, restore after)
PROLOGUE = bytes.fromhex(
    '50515253555657'
    '4150' '4151' '4152' '4153'
    '4154' '4155' '4156' '4157'
)
RESTORE = bytes.fromhex(
    '415f' '415e' '415d' '415c'
    '415b' '415a' '4159' '4158'
    '5f5e5d5b5a5958'
)
_LEA_RIP_SIZE = 7


def _lea_rip(modrm_reg: int, target_addr: int, instr_addr: int) -> bytes:
    """Assemble `lea <reg>, [rip + disp32]` pointing to `target_addr`."""
    disp = target_addr - (instr_addr + _LEA_RIP_SIZE)
    if not -RIP_REL_MAX <= disp < RIP_REL_MAX:
        raise RuntimeError(
            f'RIP-relative displacement {disp:#x} exceeds +/-2 GiB.'
        )
    return bytes([0x48, 0x8D, modrm_reg]) + struct.pack('<i', disp)


def wrap_user_code(user_code: bytes, sc_addr: int, orig_entry: int) -> bytes:
    """Wrap user_code in the boilerplate that saves GPRs and jumps to orig_entry.
    Identical to the wrapper in patcher_ptnote.py."""
    lea_offset = len(PROLOGUE) + len(user_code) + len(RESTORE)
    lea_rax = _lea_rip(0x05, orig_entry, sc_addr + lea_offset)
    jmp_rax = b'\xff\xe0'
    return PROLOGUE + user_code + RESTORE + lea_rax + jmp_rax


# Injection via relocated PHT (creates a new PT_LOAD segment)

def inject_new_segment(elf_bytes: bytes, segment_data: bytes,
                       entry_offset_in_segment: int = 0) -> bytes:
    """Add a new PT_LOAD segment by relocating the PHT to the end of the file.

    Args:
        elf_bytes:              bytes of the original ELF binary
        segment_data:           content of the new segment (shellcode with wrapper)
        entry_offset_in_segment: offset within the segment of the new entry point
                                 (e_entry will point to seg_vaddr + this offset)

    Returns:
        bytes of the modified ELF binary.

    Output file layout:
        [original ELF intact]
        [padding to page boundary]
        [new PHT: (N+1) entries]   <- new PT_LOAD starts here
        [shellcode / segment_data] <- ...and ends here
    """
    elf = ElfFile.parse(elf_bytes)
    ehdr = elf.header

    if ElfType(ehdr.e_type) not in (ElfType.EXEC, ElfType.DYN):
        raise ValueError(f'Unsupported ELF type: {ElfType(ehdr.e_type).name}')

    old_phnum = ehdr.e_phnum
    new_phnum = old_phnum + 1

    # Compute geometry of the new block at the end of the file.
    # The new block (PHT + shellcode) starts at a page boundary,
    # both in the file and in virtual memory.
    block_file_off = _align_up(len(elf_bytes), PAGE_SIZE)
    block_vaddr    = _align_up(_max_vaddr(elf), PAGE_SIZE)

    new_pht_size = new_phnum * PHDR_SIZE
    # The shellcode immediately follows the PHT, within the same segment.
    shellcode_file_off = block_file_off + new_pht_size
    shellcode_vaddr    = block_vaddr + new_pht_size

    # e_entry points to the entry offset within the shellcode
    new_entry = shellcode_vaddr + entry_offset_in_segment

    total_block_size = new_pht_size + len(segment_data)

    # Build the new PHT
    new_phdrs = []
    for seg in elf.segments:
        ph = Elf64_Phdr.from_buffer_copy(bytes(seg.header))
        # Update PT_PHDR to describe the new location of the PHT.
        if ph.p_type == PType.PHDR:
            ph.p_offset = block_file_off
            ph.p_vaddr  = block_vaddr
            ph.p_paddr  = block_vaddr
            ph.p_filesz = new_pht_size
            ph.p_memsz  = new_pht_size
        new_phdrs.append(ph)

    # New entry: PT_LOAD covering [new PHT + shellcode].
    new_load = Elf64_Phdr(
        p_type   = PType.LOAD,
        p_flags  = PF_R | PF_W | PF_X,
        p_offset = block_file_off,
        p_vaddr  = block_vaddr,
        p_paddr  = block_vaddr,
        p_filesz = total_block_size,
        p_memsz  = total_block_size,
        p_align  = PAGE_SIZE,
    )
    new_phdrs.append(new_load)

    pht_blob = b''.join(bytes(ph) for ph in new_phdrs)
    assert len(pht_blob) == new_pht_size

    # Assemble the output file
    out = bytearray(elf_bytes)
    out.extend(b'\x00' * (block_file_off - len(out)))   # padding to page boundary
    out.extend(pht_blob)                                 # new PHT
    out.extend(segment_data)                             # shellcode

    # Update the ELF header:
    # e_phoff (offset 32), e_phnum (offset 56), e_entry (offset 24)
    struct.pack_into('<Q', out, 32, block_file_off)
    struct.pack_into('<H', out, 56, new_phnum)
    struct.pack_into('<Q', out, 24, new_entry)

    log.info('PHT relocated: %d -> %d entries, new offset %#x',
             old_phnum, new_phnum, block_file_off)
    log.info('new PT_LOAD: vaddr=%#x, %d bytes (PHT %d + shellcode %d)',
             block_vaddr, total_block_size, new_pht_size, len(segment_data))
    log.info('e_entry: %#x -> %#x', ehdr.e_entry, new_entry)

    return bytes(out)


def inject_payload(elf_bytes: bytes, user_code: bytes) -> bytes:
    """Wrap user_code in the boilerplate and inject it via a new PT_LOAD segment."""
    elf = ElfFile.parse(elf_bytes)
    orig_entry = elf.header.e_entry

    # Replicate the geometry calculation from inject_new_segment
    # to determine where the shellcode will reside.
    new_phnum = elf.header.e_phnum + 1
    block_vaddr = _align_up(_max_vaddr(elf), PAGE_SIZE)
    shellcode_vaddr = block_vaddr + new_phnum * PHDR_SIZE

    full_shellcode = wrap_user_code(user_code, shellcode_vaddr, orig_entry)

    log.info('user code: %d bytes, total shellcode: %d bytes',
             len(user_code), len(full_shellcode))

    return inject_new_segment(elf_bytes, full_shellcode,
                              entry_offset_in_segment=0)


def patch_demo_write(elf_bytes: bytes, payload_size: int) -> bytes:
    """Demo mode: inject a payload and a shellcode that prints it via write."""
    elf = ElfFile.parse(elf_bytes)
    orig_entry = elf.header.e_entry

    new_phnum = elf.header.e_phnum + 1
    block_vaddr = _align_up(_max_vaddr(elf), PAGE_SIZE)
    seg_base = block_vaddr + new_phnum * PHDR_SIZE   # start of segment_data in memory

    payload = b'X' * payload_size
    buf_addr = seg_base
    code_addr = seg_base + payload_size + len(PROLOGUE)

    setup = bytes.fromhex('b801000000bf01000000')   # mov eax, 1; mov edi, 1
    lea_rsi = _lea_rip(0x35, buf_addr, code_addr + len(setup))
    mov_rdx = b'\x48\xc7\xc2' + struct.pack('<i', payload_size)
    syscall = b'\x0f\x05'
    user_code = setup + lea_rsi + mov_rdx + syscall

    sc_addr = seg_base + len(payload)
    shellcode = wrap_user_code(user_code, sc_addr, orig_entry)
    segment_data = payload + shellcode

    # e_entry must point to the shellcode (after the payload)
    return inject_new_segment(elf_bytes, segment_data,
                              entry_offset_in_segment=len(payload))


# CLI

def _parse_args(argv):
    p = argparse.ArgumentParser(
        prog='patcher_newseg',
        description='Inject code by creating a new PT_LOAD segment (relocated PHT).',
    )
    p.add_argument('input', type=Path, help='input ELF file')
    p.add_argument('-o', '--output', type=Path, default=None,
                   help='output file (default: <input>.newsegmentpatched)')
    p.add_argument('--demo-write', type=int, metavar='N',
                   help='demo mode: inject N bytes of "X" and print them via write syscall')
    p.add_argument('--payload', type=Path, metavar='F',
                   help='real mode: inject the shellcode read from F')
    p.add_argument('-q', '--quiet', action='store_true',
                   help='suppress informational messages')
    return p.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format='[newseg] %(message)s',
    )

    elf_bytes = args.input.read_bytes()
    dest = args.output or args.input.with_suffix(args.input.suffix + '.newsegmentpatched')

    try:
        if args.demo_write is not None:
            patched = patch_demo_write(elf_bytes, args.demo_write)
        elif args.payload is not None:
            patched = inject_payload(elf_bytes, args.payload.read_bytes())
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