"""patcher_ptnote.py — Injects a PT_LOAD segment into an ELF64 binary via PT_NOTE hijack.

Three operating modes:
  - analyze (default): computes injection limits without modifying the binary.
  - demo (--demo-write N): injects a payload of N 'X' bytes and a write()
    shellcode for functional validation.
  - real (--payload F): injects the shellcode read from file F.

The technique used is PT_NOTE -> PT_LOAD: an existing PT_NOTE entry in the
Program Header Table is overwritten as PT_LOAD, pointing to a region appended
at the end of the file. This preserves e_phnum and all original offsets.

The generated shellcode is position-independent — works with ET_EXEC and ET_DYN.

Reuses structures and helpers from strip.py.
"""

from __future__ import annotations

import argparse
import logging
import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'exp1_strip'))

from strip import (
    PHDR_SIZE,
    Elf64_Phdr,
    ElfFile, ElfType, PType,
)

log = logging.getLogger('patcher')

PAGE_SIZE = 0x1000

# Segment permission flags (p_flags)
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

# Maximum reach of a signed 32-bit RIP-relative displacement.
RIP_REL_MAX = 2**31


# Alignment and ELF arithmetic

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


def _find_pt_note_index(elf: ElfFile) -> int:
    """Return the index of the first PT_NOTE entry in the PHT."""
    for seg in elf.segments:
        if seg.header.p_type == PType.NOTE:
            return seg.index
    raise RuntimeError(
        'No PT_NOTE segment found. This binary does not support the '
        'PT_NOTE->PT_LOAD technique; try recompiling the target with --build-id.'
    )


# Position-independent shellcode generation

# Save all GPRs before the payload, restore afterwards. Required because
# glibc's _start expects the stack and register state to be intact.
PROLOGUE = bytes.fromhex(
    '50515253555657'                            # push rax, rcx, rdx, rbx, rbp, rsi, rdi
    '4150' '4151' '4152' '4153'                 # push r8, r9, r10, r11
    '4154' '4155' '4156' '4157'                 # push r12, r13, r14, r15
)
RESTORE = bytes.fromhex(
    '415f' '415e' '415d' '415c'                 # pop r15, r14, r13, r12
    '415b' '415a' '4159' '4158'                 # pop r11, r10, r9, r8
    '5f5e5d5b5a5958'                            # pop rdi, rsi, rbp, rbx, rdx, rcx, rax
)

_LEA_RIP_SIZE = 7
_JMP_RAX_SIZE = 2

# Fixed size of the boilerplate (PROLOGUE + RESTORE + lea rax + jmp rax).
BOILERPLATE_SIZE = len(PROLOGUE) + len(RESTORE) + _LEA_RIP_SIZE + _JMP_RAX_SIZE


def _lea_rip(modrm_reg: int, target_addr: int, instr_addr: int) -> bytes:
    """Assemble `lea <reg>, [rip + disp32]` pointing to `target_addr`."""
    disp = target_addr - (instr_addr + _LEA_RIP_SIZE)
    if not -RIP_REL_MAX <= disp < RIP_REL_MAX:
        raise RuntimeError(
            f'RIP-relative displacement {disp:#x} exceeds +/-2 GiB. '
            f'The injected segment is too far from the target address.'
        )
    return bytes([0x48, 0x8D, modrm_reg]) + struct.pack('<i', disp)


def wrap_user_code(user_code: bytes, sc_addr: int, orig_entry: int) -> bytes:
    """Wrap `user_code` in the boilerplate (prologue + epilogue) that preserves
    registers and jumps to the original entry point.

    Conventions for `user_code`:
      - May freely use all GPRs (they are restored afterwards).
      - Must return normally (no trailing `ret` or `jmp`).
      - Must be position-independent: use `lea [rip + disp]` for absolute references.

    Args:
        user_code:  bytes of the custom shellcode
        sc_addr:    virtual address of the full shellcode (including wrapper)
        orig_entry: virtual address of the original entry point
    """
    lea_offset = len(PROLOGUE) + len(user_code) + len(RESTORE)
    lea_rax = _lea_rip(0x05, orig_entry, sc_addr + lea_offset)
    jmp_rax = b'\xff\xe0'

    return PROLOGUE + user_code + RESTORE + lea_rax + jmp_rax


# Injection limit analysis

def analyze(elf_bytes: bytes) -> dict:
    """Compute theoretical injection limits for an ELF binary."""
    elf = ElfFile.parse(elf_bytes)

    if ElfType(elf.header.e_type) not in (ElfType.EXEC, ElfType.DYN):
        raise ValueError(
            f'Unsupported ELF type: {ElfType(elf.header.e_type).name}'
        )

    _find_pt_note_index(elf)

    seg_vaddr    = _align_up(_max_vaddr(elf),   PAGE_SIZE)
    seg_file_off = _align_up(len(elf_bytes),    PAGE_SIZE)
    orig_entry   = elf.header.e_entry
    distance_to_entry = abs(seg_vaddr - orig_entry)

    max_payload = RIP_REL_MAX - distance_to_entry

    if max_payload < BOILERPLATE_SIZE:
        max_user_code = 0
    else:
        max_user_code = max_payload - BOILERPLATE_SIZE

    return {
        'elf_type':           ElfType(elf.header.e_type).name,
        'orig_entry':         orig_entry,
        'seg_vaddr':          seg_vaddr,
        'seg_file_off':       seg_file_off,
        'distance_to_entry':  distance_to_entry,
        'rip_rel_limit':      RIP_REL_MAX,
        'boilerplate_size':   BOILERPLATE_SIZE,
        'max_payload':        max_payload,
        'max_user_code':      max_user_code,
    }


def print_analysis(report: dict) -> None:
    """Format the output of analyze() for human-readable display."""
    print(f"ELF type:                   {report['elf_type']}")
    print(f"Original entry point:       {report['orig_entry']:#x}")
    print(f"New segment virtual address:{report['seg_vaddr']:#x}")
    print(f"File offset:                {report['seg_file_off']:#x}")
    print(f"Distance to entry point:    {report['distance_to_entry']:,} bytes "
          f"({report['distance_to_entry']/1024/1024:.2f} MiB)")
    print()
    print(f"RIP-relative limit (lea):   {report['rip_rel_limit']:,} bytes "
          f"({report['rip_rel_limit']/1024/1024/1024:.2f} GiB)")
    print(f"Fixed wrapper overhead:     {report['boilerplate_size']} bytes "
          f"(saves GPRs + jumps to entry)")
    print()
    print(f"Maximum total payload:      {report['max_payload']:,} bytes "
          f"({report['max_payload']/1024/1024:.2f} MiB)")
    print(f"Usable space for user code: {report['max_user_code']:,} bytes "
          f"({report['max_user_code']/1024/1024:.2f} MiB)")


# Injection

def inject_segment(elf_bytes: bytes, segment_data: bytes,
                   new_entry: int) -> bytes:
    """Append a PT_LOAD segment to the ELF via PT_NOTE hijack."""
    elf = ElfFile.parse(elf_bytes)

    if ElfType(elf.header.e_type) not in (ElfType.EXEC, ElfType.DYN):
        raise ValueError(
            f'Unsupported ELF type: {ElfType(elf.header.e_type).name}'
        )

    note_idx = _find_pt_note_index(elf)
    seg_file_off = _align_up(len(elf_bytes), PAGE_SIZE)
    seg_vaddr    = _align_up(_max_vaddr(elf),  PAGE_SIZE)

    # 1. Extend buffer to seg_file_off and append the segment data.
    out = bytearray(elf_bytes)
    out.extend(b'\x00' * (seg_file_off - len(out)))
    out.extend(segment_data)

    # 2. Overwrite the PT_NOTE entry as PT_LOAD.
    new_phdr = Elf64_Phdr(
        p_type   = PType.LOAD,
        p_flags  = PF_R | PF_W | PF_X,
        p_offset = seg_file_off,
        p_vaddr  = seg_vaddr,
        p_paddr  = seg_vaddr,
        p_filesz = len(segment_data),
        p_memsz  = len(segment_data),
        p_align  = PAGE_SIZE,
    )
    phdr_off = elf.header.e_phoff + note_idx * elf.header.e_phentsize
    out[phdr_off : phdr_off + PHDR_SIZE] = bytes(new_phdr)

    # 3. Update e_entry in the ELF header (offset 24).
    struct.pack_into('<Q', out, 24, new_entry)

    log.info('PT_NOTE[%d] -> PT_LOAD at vaddr=%#x (file_off=%#x, %d bytes)',
             note_idx, seg_vaddr, seg_file_off, len(segment_data))
    log.info('e_entry: %#x -> %#x', elf.header.e_entry, new_entry)

    return bytes(out)


def inject_payload(elf_bytes: bytes, user_code: bytes) -> bytes:
    """Wrap `user_code` in the boilerplate and inject it into the ELF.

    The wrapper saves GPRs, executes user_code, restores GPRs, and jumps
    to the original entry point.
    """
    elf = ElfFile.parse(elf_bytes)
    orig_entry = elf.header.e_entry
    seg_vaddr = _align_up(_max_vaddr(elf), PAGE_SIZE)

    full_shellcode = wrap_user_code(user_code, seg_vaddr, orig_entry)

    log.info('user code: %d bytes', len(user_code))
    log.info('total shellcode (with wrapper): %d bytes', len(full_shellcode))

    return inject_segment(elf_bytes, full_shellcode, new_entry=seg_vaddr)


# Demo: write() shellcode for functional validation

def patch_demo_write(elf_bytes: bytes, payload_size: int) -> bytes:
    """Demo mode: inject a payload and a shellcode that prints it."""
    elf = ElfFile.parse(elf_bytes)
    orig_entry = elf.header.e_entry
    seg_vaddr  = _align_up(_max_vaddr(elf), PAGE_SIZE)

    payload = b'X' * payload_size
    buf_addr = seg_vaddr
    code_addr = seg_vaddr + payload_size + len(PROLOGUE)

    # mov eax, 1 (sys_write); mov edi, 1 (stdout)
    setup = bytes.fromhex('b801000000bf01000000')
    lea_rsi = _lea_rip(0x35, buf_addr, code_addr + len(setup))
    mov_rdx = b'\x48\xc7\xc2' + struct.pack('<i', payload_size)
    syscall = b'\x0f\x05'
    user_code = setup + lea_rsi + mov_rdx + syscall

    sc_addr = seg_vaddr + len(payload)
    shellcode = wrap_user_code(user_code, sc_addr, orig_entry)
    segment_data = payload + shellcode

    log.info('demo: payload %d bytes, shellcode %d bytes, total %d bytes',
             len(payload), len(shellcode), len(segment_data))

    return inject_segment(elf_bytes, segment_data, new_entry=sc_addr)


# CLI

def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog='patcher_ptnote',
        description='Inject a PT_LOAD segment into an ELF64 binary via PT_NOTE hijack. '
                    'Without flags, analyzes injection limits. With --demo-write N '
                    'injects a test payload. With --payload F injects the shellcode '
                    'read from F.',
    )
    p.add_argument('input', type=Path, help='input ELF file')
    p.add_argument('-o', '--output', type=Path, default=None,
                   help='output file (default: <input>.patched)')
    p.add_argument('--demo-write', type=int, metavar='N',
                   help='demo mode: inject N bytes of "X" and print them via write syscall')
    p.add_argument('--payload', type=Path, metavar='F',
                   help='real mode: inject the shellcode read from F '
                        '(must be position-independent)')
    p.add_argument('-q', '--quiet', action='store_true',
                   help='suppress informational messages')
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format='[patcher] %(message)s',
    )

    if args.demo_write is not None and args.payload is not None:
        log.error('--demo-write and --payload are mutually exclusive')
        return 2

    try:
        elf_bytes = args.input.read_bytes()
    except OSError as e:
        log.error('%s', e)
        return 1

    # Default mode: analysis (when neither --demo-write nor --payload is given)
    if args.demo_write is None and args.payload is None:
        try:
            report = analyze(elf_bytes)
        except (ValueError, RuntimeError) as e:
            log.error('%s', e)
            return 1
        print_analysis(report)
        return 0

    # Injection modes
    dest = args.output or args.input.with_suffix(args.input.suffix + '.patched')

    try:
        if args.demo_write is not None:
            patched = patch_demo_write(elf_bytes, args.demo_write)
        else:
            user_code = args.payload.read_bytes()
            patched = inject_payload(elf_bytes, user_code)
        dest.write_bytes(patched)
        os.chmod(dest, args.input.stat().st_mode & 0o7777)
    except (ValueError, RuntimeError, OSError) as e:
        log.error('%s', e)
        return 1
    except Exception:
        log.exception('unhandled error')
        return 1

    log.info('%s: %s bytes (original: %s bytes)',
             dest, f'{len(patched):,}', f'{len(elf_bytes):,}')
    return 0


if __name__ == '__main__':
    sys.exit(main())