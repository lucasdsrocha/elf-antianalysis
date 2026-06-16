from __future__ import annotations

import argparse
import ctypes
import enum
import logging
import os
import struct
import sys
from dataclasses import dataclass, replace
from pathlib import Path

log = logging.getLogger('strip')


class ElfClass(enum.IntEnum):
    NONE  = 0
    ELF32 = 1
    ELF64 = 2


class ElfData(enum.IntEnum):
    NONE = 0
    LSB  = 1   # little-endian
    MSB  = 2   # big-endian


class ElfType(enum.IntEnum):
    NONE = 0
    REL  = 1   # relocatable object (.o)
    EXEC = 2   # executable
    DYN  = 3   # shared object / PIE
    CORE = 4   # core dump (out of scope)


class PType(enum.IntEnum):
    NULL    = 0
    LOAD    = 1
    DYNAMIC = 2
    INTERP  = 3
    NOTE    = 4
    SHLIB   = 5
    PHDR    = 6
    TLS     = 7


class ShType(enum.IntEnum):
    NULL     = 0
    PROGBITS = 1
    SYMTAB   = 2
    STRTAB   = 3
    RELA     = 4
    HASH     = 5
    DYNAMIC  = 6
    NOTE     = 7
    NOBITS   = 8
    REL      = 9
    SHLIB    = 10
    DYNSYM   = 11


class ShFlags(enum.IntFlag):
    WRITE      = 0x1
    ALLOC      = 0x2
    EXECINSTR  = 0x4
    MERGE      = 0x10
    STRINGS    = 0x20
    INFO_LINK  = 0x40   # sh_info holds a section index (RELA/REL)
    LINK_ORDER = 0x80
    GROUP      = 0x200
    TLS        = 0x400


# Reserved indices for 16-bit index fields (e_shstrndx, st_shndx)
SHN_UNDEF  = 0
SHN_XINDEX = 0xffff   # real index is stored in sh_link of section 0

# ELF magic number constant
ELF_MAGIC = b'\x7fELF'

# Strip policy: prefixes and specific names for ET_REL objects.
# For ET_EXEC/ET_DYN the policy differs (keep only ALLOC sections),
# so these lists apply only to the relocatable object path.
_DEBUG_PREFIXES = (b'.debug_', b'.zdebug_')
_REMOVE_NAMES = frozenset({
    b'.comment',
    b'.gnu_debuglink',
    b'.gnu_debugaltlink',
    b'.gdb_index',
})

# ELF64 ctypes structures

# 64-byte ELF header structure, based on the System V ABI specification.
class Elf64_Ehdr(ctypes.LittleEndianStructure):
    _pack_ = 1 #disables implicit paddin between fields, matching the ELF64 
    _fields_ = [
        ('e_ident',     ctypes.c_uint8 * 16), # Identification bytes (Magic, Class, Data, Version, OSABI, ABIVersion, Padding)
        ('e_type',      ctypes.c_uint16), # File type (ET_REL, ET_EXEC, ET_DYN)
        ('e_machine',   ctypes.c_uint16), # Target architecture (0x3E for x86_64)
        ('e_version',   ctypes.c_uint32), # ELF version (always 1)
        ('e_entry',     ctypes.c_uint64), # Virtual entry point address
        ('e_phoff',     ctypes.c_uint64), # Offset of the Program Header Table
        ('e_shoff',     ctypes.c_uint64), # Offset of the Section Header Table
        ('e_flags',     ctypes.c_uint32), # Processor-specific flags
        ('e_ehsize',    ctypes.c_uint16), # Size of this ELF header
        ('e_phentsize', ctypes.c_uint16), # Size of one Program Header Table entry
        ('e_phnum',     ctypes.c_uint16), # Number of Program Header Table entries
        ('e_shentsize', ctypes.c_uint16), # Size of one Section Header Table entry
        ('e_shnum',     ctypes.c_uint16), # Number of Section Header Table entries
        ('e_shstrndx',  ctypes.c_uint16), # Index of the section name string table
    ]  # 64 bytes


class Elf64_Shdr(ctypes.LittleEndianStructure):
    _pack_ = 1 #disables implicit paddin between fields, matching the ELF64
    _fields_ = [
        ('sh_name',      ctypes.c_uint32), # Offset of section name in .shstrtab
        ('sh_type',      ctypes.c_uint32), # Section type (SHT_PROGBITS, SHT_SYMTAB, etc.)
        ('sh_flags',     ctypes.c_uint64), # Section flags
        ('sh_addr',      ctypes.c_uint64), # Virtual address of section
        ('sh_offset',    ctypes.c_uint64), # Offset of section in file
        ('sh_size',      ctypes.c_uint64), # Size of section in bytes
        ('sh_link',      ctypes.c_uint32), # Link to another section (type-dependent)
        ('sh_info',      ctypes.c_uint32), # Additional section information (type-dependent)
        ('sh_addralign', ctypes.c_uint64), # Section alignment constraint
        ('sh_entsize',   ctypes.c_uint64), # Size of each entry, if section holds a table
    ]  # 64 bytes


class Elf64_Phdr(ctypes.LittleEndianStructure):
    _pack_ = 1 #disables implicit paddin between fields, matching the ELF64
    _fields_ = [
        ('p_type',   ctypes.c_uint32), # Segment type (PT_LOAD, PT_DYNAMIC, etc.)
        ('p_flags',  ctypes.c_uint32), # Segment flags (R, W, X)
        ('p_offset', ctypes.c_uint64), # Offset of segment in file
        ('p_vaddr',  ctypes.c_uint64), # Virtual address of segment
        ('p_paddr',  ctypes.c_uint64), # Physical address of segment
        ('p_filesz', ctypes.c_uint64), # Size of segment in file
        ('p_memsz',  ctypes.c_uint64), # Size of segment in memory
        ('p_align',  ctypes.c_uint64), # Segment alignment
    ]  # 56 bytes


EHDR_SIZE = ctypes.sizeof(Elf64_Ehdr)   # 64
SHDR_SIZE = ctypes.sizeof(Elf64_Shdr)   # 64
PHDR_SIZE = ctypes.sizeof(Elf64_Phdr)   # 56

@dataclass(frozen=True)
class Section:
    """An ELF section with its header, resolved name and raw data.

    For SHT_NOBITS (.bss), data is b'', but header.sh_size holds the
    logical size — consumers must read header.sh_size, not len(data).
    """
    index: int                # original index in the SHT (useful for debugging)
    header: Elf64_Shdr
    name: bytes               # name resolved from .shstrtab
    data: bytes


@dataclass(frozen=True)
class Segment:
    """A Program Header Table entry."""
    index: int
    header: Elf64_Phdr


@dataclass(frozen=True)
class ElfFile:
    """Complete in-memory representation of a 64-bit little-endian ELF file.

    Constructed via ElfFile.parse(data). After transformations (e.g. strip_all)
    the result is a new ElfFile, which can be serialized via to_bytes().
    """
    header: Elf64_Ehdr
    sections: list[Section]
    segments: list[Segment]
    shstrndx: int             # resolved index (SHN_XINDEX already handled)

    @classmethod
    def parse(cls, data: bytes) -> ElfFile:
        """Load an ELF64 LSB file from raw bytes.

        Raises ValueError if the format is not supported.
        """
        cls._validate_magic(data)
        ehdr = Elf64_Ehdr.from_buffer_copy(data)

        if ehdr.e_shnum == 0:
            # No SHT means nothing to strip (already maximally stripped).
            # Return a valid ElfFile so the caller can decide what to do.
            return cls(header=ehdr, sections=[], segments=[],
                       shstrndx=SHN_UNDEF)

        shstrndx = cls._resolve_shstrndx(data, ehdr)

        # Read all section headers
        raw_shdrs = [
            cls._read_shdr(data, ehdr, i)
            for i in range(ehdr.e_shnum)
        ]

        # Read .shstrtab to resolve section names
        shstr_hdr = raw_shdrs[shstrndx]
        shstrtab = bytes(data[
            shstr_hdr.sh_offset : shstr_hdr.sh_offset + shstr_hdr.sh_size
        ])

        sections = []
        for i, sh in enumerate(raw_shdrs):
            name = _cstring_at(shstrtab, sh.sh_name)
            sec_data = cls._read_section_data(data, sh)
            sections.append(Section(index=i, header=sh, name=name,
                                    data=sec_data))

        # Program headers (may not exist in ET_REL objects)
        segments = [
            Segment(index=i, header=cls._read_phdr(data, ehdr, i))
            for i in range(ehdr.e_phnum)
        ]

        return cls(header=ehdr, sections=sections, segments=segments,
                   shstrndx=shstrndx)


    @staticmethod
    def _validate_magic(data: bytes) -> None:
        if len(data) < EHDR_SIZE:
            raise ValueError('File is smaller than the ELF header (64 bytes)')
        if data[:4] != ELF_MAGIC:
            raise ValueError('Not an ELF file (expected magic 0x7F 45 4C 46)')
        if data[4] != ElfClass.ELF64:
            raise ValueError('Only ELF64 is supported (EI_CLASS != ELFCLASS64)')
        if data[5] != ElfData.LSB:
            raise ValueError(
                'Only little-endian is supported (EI_DATA != ELFDATA2LSB)'
            )

    @staticmethod
    def _resolve_shstrndx(data: bytes, ehdr: Elf64_Ehdr) -> int:
        """Resolve the .shstrtab index, handling SHN_XINDEX.

        When e_shstrndx == 0xffff (SHN_XINDEX), the real index is stored
        in sh_link of section 0 — an escape mechanism for files with more
        than 0xff00 sections.
        """
        idx = ehdr.e_shstrndx
        if idx == SHN_XINDEX:
            sh0 = ElfFile._read_shdr(data, ehdr, 0)
            idx = sh0.sh_link
        if idx == SHN_UNDEF:
            raise ValueError('e_shstrndx == 0: file has no .shstrtab')
        if idx >= ehdr.e_shnum:
            raise ValueError(
                f'e_shstrndx ({idx}) is out of range [0, {ehdr.e_shnum})'
            )
        return idx


    @staticmethod
    def _read_shdr(data: bytes, ehdr: Elf64_Ehdr, idx: int) -> Elf64_Shdr:
        off = ehdr.e_shoff + idx * ehdr.e_shentsize
        return Elf64_Shdr.from_buffer_copy(data[off : off + SHDR_SIZE])

    @staticmethod
    def _read_phdr(data: bytes, ehdr: Elf64_Ehdr, idx: int) -> Elf64_Phdr:
        off = ehdr.e_phoff + idx * ehdr.e_phentsize
        return Elf64_Phdr.from_buffer_copy(data[off : off + PHDR_SIZE])

    @staticmethod
    def _read_section_data(data: bytes, sh: Elf64_Shdr) -> bytes:
        # SHT_NOBITS (.bss) has no data in the file, only reserved memory space.
        # Return b'' and rely on sh_size for the logical size.
        if sh.sh_type == ShType.NOBITS:
            return b''
        return bytes(data[sh.sh_offset : sh.sh_offset + sh.sh_size])


    def find_section(self, name: bytes) -> Section | None:
        """Return the first section with the given name, or None."""
        for sec in self.sections:
            if sec.name == name:
                return sec
        return None

    def symtab_indices(self) -> set[int]:
        """Original indices of SHT_SYMTAB sections."""
        return {s.index for s in self.sections
                if s.header.sh_type == ShType.SYMTAB}

    def symtab_strtab_indices(self) -> set[int]:
        """Original indices of .strtab sections linked to a SHT_SYMTAB
        (via sh_link). Required to remove them together with the symtab."""
        return {s.header.sh_link for s in self.sections
                if s.header.sh_type == ShType.SYMTAB and s.header.sh_link != 0}


    def to_bytes(self) -> bytes:
        """Serialize the ElfFile into bytes ready to be written to disk.

        Dispatches between two strategies:
          - ET_EXEC/ET_DYN: truncate after the last PT_LOAD and rewrite the SHT.
          - ET_REL: repack sections (no PHT, no PT_LOAD).
        """
        et = ElfType(self.header.e_type)
        if et in (ElfType.EXEC, ElfType.DYN):
            return _serialize_exec_dyn(self)
        elif et == ElfType.REL:
            return _serialize_rel(self)
        else:
            raise ValueError(f'Unsupported ELF type: {et.name}')

# These functions take an ElfFile and return a new ElfFile. They do not
# touch raw bytes directly — they only decide which sections survive.
# Serialization happens afterwards in to_bytes().

def strip_all(elf: ElfFile) -> ElfFile:
    """Equivalent to `strip --strip-all`: removes symbols, debug info and metadata.

    Differentiated policy by object type:
      - ET_EXEC/ET_DYN: keep only the NULL section and sections with SHF_ALLOC.
        Everything outside PT_LOAD segments is discarded during truncation.
      - ET_REL: selective removal (symtab, linked strtab, .debug_*,
        orphan relocations, .comment, etc.).
    """
    if not elf.sections:
        return elf

    et = ElfType(elf.header.e_type)
    if et in (ElfType.EXEC, ElfType.DYN):
        keep = _select_exec_dyn(elf)
    elif et == ElfType.REL:
        keep = _select_rel(elf)
    else:
        raise ValueError(f'Unsupported ELF type for strip: {et.name}')

    # Log removed sections (useful for debugging and thesis reports)
    kept_indices = {s.index for s in keep}
    for sec in elf.sections:
        if sec.index not in kept_indices:
            label = sec.name.decode(errors='replace') or 'NULL'
            log.info('removing section %3d %r', sec.index, label)

    # Resulting ElfFile: selected sections only; SHT will be recalculated
    # during serialization. shstrndx is meaningless here (rebuilt by the writer).
    return replace(elf, sections=keep)


def _select_exec_dyn(elf: ElfFile) -> list[Section]:
    """Selection policy for ET_EXEC and ET_DYN: NULL + SHF_ALLOC.

    Everything outside PT_LOAD segments (debug, symtab, strtab, comment,
    old SHT) is discarded during truncation in the serialization layer.
    """
    return [
        s for s in elf.sections
        if s.index == 0 or bool(s.header.sh_flags & ShFlags.ALLOC)
    ]


def _select_rel(elf: ElfFile) -> list[Section]:
    """Selection policy for ET_REL: selective removal by type, name and relation."""
    symtab_idx = elf.symtab_indices()
    strtab_of_symtab = elf.symtab_strtab_indices()

    return [s for s in elf.sections
            if not _should_remove_rel(s, symtab_idx, strtab_of_symtab)]


def _should_remove_rel(sec: Section,
                       symtab_indices: set[int],
                       symtab_strtab_indices: set[int]) -> bool:
    """Removal predicate for sections in relocatable objects."""
    sh = sec.header
    name = sec.name

    # NEVER remove section 0 (NULL) — required by the ELF specification
    if sec.index == 0 or sh.sh_type == ShType.NULL:
        return False

    # Static symbol table (keeps .dynsym, which has a different type)
    if sh.sh_type == ShType.SYMTAB:
        return True

    # .strtab linked to a symtab that will be removed
    if sec.index in symtab_strtab_indices:
        return True

    # Relocations pointing to a removed symtab (sh_link → symtab)
    if sh.sh_type in (ShType.RELA, ShType.REL) and sh.sh_link in symtab_indices:
        return True

    # DWARF debug sections (.debug_info, .debug_line, .zdebug_*, ...)
    if any(name.startswith(p) for p in _DEBUG_PREFIXES):
        return True

    # Toolchain metadata and auxiliary debugging information
    if name in _REMOVE_NAMES:
        return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Serialization layer
# ─────────────────────────────────────────────────────────────────────────────
#
# Private functions called by ElfFile.to_bytes(). The split by object type
# reflects two fundamentally different strategies (linking view vs execution view).

def _serialize_exec_dyn(elf: ElfFile) -> bytes:
    """Serialization strategy for ET_EXEC and ET_DYN.

    Every SHF_ALLOC section lives inside a PT_LOAD segment in the file. We
    truncate at the end of the last PT_LOAD (discarding .symtab, .strtab,
    .debug_*, and the old SHT) and append a minimal SHT at the end.

    The sh_offset values of kept sections remain valid without adjustment,
    since they point into the region [0, vital_end) that was preserved.
    """
    # Determine the end of the last "vital" region (PT_LOAD)
    vital_end = elf.header.e_ehsize
    for seg in elf.segments:
        ph = seg.header
        if ph.p_type == PType.LOAD and ph.p_filesz > 0:
            vital_end = max(vital_end, ph.p_offset + ph.p_filesz)

    log.info('end of PT_LOAD segments: %#x', vital_end)

    # Recover original bytes up to vital_end. Since the transformation did not
    # modify section data (only removed some sections), we can reconstruct the
    # vital region by placing each kept section back at its original offset.
    buf = bytearray(_reconstruct_original_prefix(elf, vital_end))

    # Append new .shstrtab + aligned SHT
    new_shstrtab, name_offsets = _build_shstrtab(elf.sections)
    shstrtab_off = len(buf)
    buf.extend(new_shstrtab)
    _align_to(buf, 8)

    off_sht = _append_section_header_table(
        buf, elf.sections, name_offsets, shstrtab_off, len(new_shstrtab)
    )

    # Update ELF header: new e_shoff, e_shnum, e_shstrndx
    _patch_ehdr(buf, off_sht, len(elf.sections) + 1, len(elf.sections))

    return bytes(buf)


def _serialize_rel(elf: ElfFile) -> bytes:
    """Serialization strategy for ET_REL (relocatable objects).

    Without PT_LOAD segments there is no "vital end" to truncate at.
    We repack each kept section in sequence, recalculating sh_offset.
    SHT_NOBITS sections consume no bytes but still need a valid offset.
    """
    # Start with only the ELF header (will be patched at the end)
    buf = bytearray(bytes(elf.header))

    new_offsets: dict[int, int] = {}    # new_idx → offset in the new file
    end_of_data = EHDR_SIZE             # tracks end of the data area

    for new_idx, sec in enumerate(elf.sections):
        sh = sec.header

        if new_idx == 0 or sh.sh_size == 0:
            new_offsets[new_idx] = 0
            continue

        if sh.sh_type == ShType.NOBITS:
            # No data in file; offset points to the current end of data area
            new_offsets[new_idx] = end_of_data
            continue

        align = max(1, sh.sh_addralign)
        _align_to(buf, align)

        new_offsets[new_idx] = len(buf)
        buf.extend(sec.data)
        end_of_data = len(buf)

    # Append new .shstrtab
    new_shstrtab, name_offsets = _build_shstrtab(elf.sections)
    shstrtab_off = len(buf)
    buf.extend(new_shstrtab)
    _align_to(buf, 8)

    # Write SHT with updated offsets
    off_sht = len(buf)
    for new_idx, sec in enumerate(elf.sections):
        sh2 = Elf64_Shdr.from_buffer_copy(bytes(sec.header))
        sh2.sh_name = name_offsets[new_idx]

        if sh2.sh_size > 0 and new_idx > 0:
            sh2.sh_offset = new_offsets[new_idx]

        _remap_cross_references(sh2, elf.sections)
        buf.extend(bytes(sh2))

    # Header for the new .shstrtab
    buf.extend(_make_shstrtab_header(
        name_offset=name_offsets[len(elf.sections)],
        offset=shstrtab_off,
        size=len(new_shstrtab),
    ))

    _patch_ehdr(buf, off_sht, len(elf.sections) + 1, len(elf.sections))
    return bytes(buf)


# ── Serialization helpers ────────────────────────────────────────────────────

def _reconstruct_original_prefix(elf: ElfFile, vital_end: int) -> bytes:
    """Reconstruct bytes [0, vital_end) preserving the original layout.

    Since section data inside PT_LOAD segments was not modified, we build
    a zeroed region and copy each kept section back at its original offset.
    """
    buf = bytearray(vital_end)

    # Copy ELF header
    buf[0:EHDR_SIZE] = bytes(elf.header)

    # Copy program header table
    if elf.header.e_phoff > 0:
        for seg in elf.segments:
            off = elf.header.e_phoff + seg.index * elf.header.e_phentsize
            buf[off : off + PHDR_SIZE] = bytes(seg.header)

    # Copy data of sections that fall within the vital prefix
    for sec in elf.sections:
        if sec.header.sh_type == ShType.NOBITS:
            continue
        off = sec.header.sh_offset
        size = sec.header.sh_size
        if off + size <= vital_end and size > 0:
            buf[off : off + size] = sec.data

    return bytes(buf)


def _build_shstrtab(sections: list[Section]) -> tuple[bytes, list[int]]:
    """Build a new .shstrtab containing only the names of kept sections
    plus the '.shstrtab' entry for the section itself.

    Returns (blob, offsets) where:
      - offsets[i] is the offset of the i-th section name in `sections`
      - offsets[len(sections)] is the offset of the '.shstrtab' name
    """
    blob = bytearray(b'\x00')   # position 0 = empty string (NULL section)
    cache: dict[bytes, int] = {}
    offsets: list[int] = []

    for sec in sections:
        name = sec.name
        if not name:
            offsets.append(0)
        elif name in cache:
            offsets.append(cache[name])
        else:
            pos = len(blob)
            cache[name] = pos
            blob.extend(name + b'\x00')
            offsets.append(pos)

    # Entry for the .shstrtab section itself
    shstrtab_name = b'.shstrtab'
    if shstrtab_name in cache:
        offsets.append(cache[shstrtab_name])
    else:
        offsets.append(len(blob))
        blob.extend(shstrtab_name + b'\x00')

    return bytes(blob), offsets


def _build_index_map(sections: list[Section]) -> dict[int, int]:
    """Map original_index → new_index, used to remap sh_link/sh_info."""
    return {sec.index: new_idx for new_idx, sec in enumerate(sections)}


def _remap_cross_references(sh: Elf64_Shdr, sections: list[Section]) -> None:
    """Update sh_link and sh_info if they reference old section indices.

    sh_link is always a section index when != 0.
    sh_info is a section index only when SHF_INFO_LINK is set (RELA/REL).
    """
    idx_map = _build_index_map(sections)

    if sh.sh_link != 0:
        sh.sh_link = idx_map.get(sh.sh_link, 0)
    if sh.sh_flags & ShFlags.INFO_LINK:
        sh.sh_info = idx_map.get(sh.sh_info, 0)


def _append_section_header_table(buf: bytearray, sections: list[Section],
                                 name_offsets: list[int],
                                 shstrtab_off: int,
                                 shstrtab_size: int) -> int:
    """Write the SHT at the end of `buf` and return the offset where it started.

    Precondition: `buf` must already be aligned to 8 bytes (caller's responsibility).
    """
    off_sht = len(buf)

    for new_idx, sec in enumerate(sections):
        sh2 = Elf64_Shdr.from_buffer_copy(bytes(sec.header))
        sh2.sh_name = name_offsets[new_idx]
        _remap_cross_references(sh2, sections)
        buf.extend(bytes(sh2))

    # Header for the .shstrtab section (always the last entry)
    buf.extend(_make_shstrtab_header(
        name_offset=name_offsets[len(sections)],
        offset=shstrtab_off,
        size=shstrtab_size,
    ))

    return off_sht


def _make_shstrtab_header(name_offset: int, offset: int,
                          size: int) -> bytes:
    """Create an Elf64_Shdr for a newly built .shstrtab section."""
    sh = Elf64_Shdr()
    sh.sh_name      = name_offset
    sh.sh_type      = ShType.STRTAB
    sh.sh_offset    = offset
    sh.sh_size      = size
    sh.sh_addralign = 1
    return bytes(sh)


def _patch_ehdr(buf: bytearray, e_shoff: int, e_shnum: int,
                e_shstrndx: int) -> None:
    """Update the three ELF header fields that depend on the new SHT."""
    # Offsets come from the Elf64_Ehdr definition (System V ABI)
    struct.pack_into('<Q', buf, 40, e_shoff)       # e_shoff    (offset 40)
    struct.pack_into('<H', buf, 60, e_shnum)        # e_shnum   (offset 60)
    struct.pack_into('<H', buf, 62, e_shstrndx)     # e_shstrndx (offset 62)


def _align_to(buf: bytearray, alignment: int) -> None:
    """Extend `buf` with zero bytes until its length is a multiple of `alignment`."""
    while len(buf) % alignment:
        buf.append(0)


def _cstring_at(blob: bytes, offset: int) -> bytes:
    r"""Read a NUL-terminated C string starting at `offset` in `blob`."""
    end = blob.find(b'\x00', offset)
    return blob[offset:end] if end != -1 else b''


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def strip_file(input_path: Path, output_path: Path | None = None) -> Path:
    """Read the input ELF, apply strip_all, and write to the destination.

    If `output_path` is None, the input file is overwritten in place.
    Preserves the file permissions of the original file.
    Returns the path of the generated file.
    """
    raw = input_path.read_bytes()
    elf = ElfFile.parse(raw)

    if not elf.sections:
        log.warning('file has no section headers — nothing to do')
        return input_path

    stripped = strip_all(elf)
    output_bytes = stripped.to_bytes()

    dest = output_path if output_path is not None else input_path
    dest.write_bytes(output_bytes)

    # Preserve input file permissions (including the execute bit),
    # which is the expected behaviour of any strip/objcopy-like tool.
    src_mode = input_path.stat().st_mode & 0o7777
    os.chmod(dest, src_mode)

    log.info('%s: %s bytes (original: %s bytes)',
             dest, f'{len(output_bytes):,}', f'{len(raw):,}')
    return dest


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog='strip',
        description='Remove symbols and metadata from an ELF64 LSB binary '
                    '(didactic implementation of strip --strip-all).',
    )
    p.add_argument('input', type=Path, help='input ELF file')
    p.add_argument('-o', '--output', type=Path, default=None,
                   help='output file (default: <input>.stripped)')
    p.add_argument('--in-place', action='store_true',
                   help='overwrite the input file')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='show each removed section')
    p.add_argument('-q', '--quiet', action='store_true',
                   help='suppress informational messages')
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    # Logging configuration
    if args.quiet:
        level = logging.WARNING
    else:
        level = logging.INFO
    logging.basicConfig(level=level, format='[strip] %(message)s')

    # Resolve destination
    if args.in_place and args.output:
        log.error('--in-place and --output are mutually exclusive')
        return 2

    if args.in_place:
        output = args.input
    elif args.output:
        output = args.output
    else:
        output = args.input.with_suffix(args.input.suffix + '.stripped')

    try:
        strip_file(args.input, output)
    except (ValueError, OSError) as e:
        log.error('%s', e)
        return 1
    except Exception:
        log.exception('unhandled error')
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())