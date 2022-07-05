package elfmap

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

/*
   This file is mostly copy/paste from debug/elf and tried to reuse as much as possible the debug/elf implementation

   Scope: Parsing ELF library directly from memory, thanks to the help of /proc/pid/maps when we don't have access to .so library file
          In /proc/pid/maps not the whole ELF file is mapped in memory, some section are missing or incomplete.

   This implementation try to reuse as much as possible the debug/elf implementation, but has some specificities/limitation :
    o Don't failed when we can't resolv section name: some sections are missing or incomplete
    o Don't support compression headers : ELF section are not compressed in memory
    o Doesn't check gnuVersion() : we don't need gnu/version library info for the resolution
    o Recover SYMTAB and STRTAB offset from PT_DYNAMIC tags (prog section) and rebuild corresponding ELF sections
*/

type ElfMap struct {
	libraryFile *os.File
	Elf         *elf.File
}

func (e *ElfMap) Close() error {
	if e.libraryFile != nil {
		if err := e.libraryFile.Close(); err != nil {
			return err
		}
	}
	if err := e.Elf.Close(); err != nil {
		return err
	}
	return nil
}

func OpenMapBytes(elfmap *bytes.Reader, vBaseAddr uintptr) (*ElfMap, error) {
	var err error
	e := &ElfMap{}
	e.Elf, err = NewFile(elfmap, vBaseAddr, elfmap.Size())
	if err != nil {
		return nil, err
	}
	return e, nil
}

func Open(name string) (*ElfMap, error) {
	var err error
	e := &ElfMap{}
	e.libraryFile, err = os.Open(name)
	if err != nil {
		return nil, err
	}
	fstat, err := e.libraryFile.Stat()
	if err != nil {
		return nil, err
	}
	e.Elf, err = NewFile(e.libraryFile, uintptr(0), fstat.Size())
	if err != nil {
		e.libraryFile.Close()
		return nil, err
	}
	return e, nil
}

type FormatError struct {
	off int64
	msg string
	val interface{}
}

func (e *FormatError) Error() string {
	msg := e.msg
	if e.val != nil {
		msg += fmt.Sprintf(" '%v' ", e.val)
	}
	msg += fmt.Sprintf("in record at byte %#x", e.off)
	return msg

}

func (e *ElfMap) Symbols() ([]elf.Symbol, error) {
	return symbols(e.Elf)
}

// Symbols returns the symbol table for f. The symbols will be listed in the order
// they appear in f.
//
// For compatibility with Go 1.0, Symbols omits the null symbol at index 0.
// After retrieving the symbols as symtab, an externally supplied index x
// corresponds to symtab[x-1], not symtab[x].
func symbols(f *elf.File) ([]elf.Symbol, error) {
	sym, _, err := getSymbols(f, elf.SHT_SYMTAB)
	return sym, err
}

func (e *ElfMap) DynamicSymbols() ([]elf.Symbol, error) {
	return dynamicSymbols(e.Elf)
}

// DynamicSymbols returns the dynamic symbol table for f. The symbols
// will be listed in the order they appear in f.
//
// If f has a symbol version table, the returned Symbols will have
// initialized Version and Library fields.
//
// For compatibility with Symbols, DynamicSymbols omits the null symbol at index 0.
// After retrieving the symbols as symtab, an externally supplied index x
// corresponds to symtab[x-1], not symtab[x].
func dynamicSymbols(f *elf.File) ([]elf.Symbol, error) {
	sym, _, err := getSymbols(f, elf.SHT_DYNSYM)
	if err != nil {
		return nil, err
	}
	/* ignoring GNU library version */
	/*
		if f.gnuVersionInit(str) {
			for i := range sym {
				sym[i].Library, sym[i].Version = f.gnuVersion(i)
			}
		}
	*/
	return sym, nil
}

// getString extracts a string from an ELF string table.
func getString(section []byte, start int) (string, bool) {
	if start < 0 || start >= len(section) {
		return "", false
	}
	for end := start; end < len(section); end++ {
		if section[end] == 0 {
			return string(section[start:end]), true
		}
	}
	return "", false

}

// seekStart, seekCurrent, seekEnd are copies of
// io.SeekStart, io.SeekCurrent, and io.SeekEnd.
// We can't use the ones from package io because
// we want this code to build with Go 1.4 during
// cmd/dist bootstrap.

const (
	seekStart   int = 0
	seekCurrent int = 1
	seekEnd     int = 2
)

// stringTable reads and returns the string table given by the
// specified link value.
func stringTable(f *elf.File, link uint32) ([]byte, error) {
	if link <= 0 || link >= uint32(len(f.Sections)) {
		return nil, errors.New("section has invalid string table link")
	}
	return readElfSectionData(f.Sections[link])
}

func getSymbols32(f *elf.File, typ elf.SectionType) ([]elf.Symbol, []byte, error) {
	symtabSection := f.SectionByType(typ)
	if symtabSection == nil {
		return nil, nil, elf.ErrNoSymbols
	}
	data, err := symtabSection.Data()
	if err != nil {
		return nil, nil, errors.New("cannot load symbol section")
	}
	symtab := bytes.NewReader(data)
	if symtab.Len()%elf.Sym32Size != 0 {
		return nil, nil, errors.New("length of symbol section is not a multiple of SymSize")
	}
	strdata, err := stringTable(f, symtabSection.Link)
	if err != nil {
		return nil, nil, errors.New("cannot load string table section")
	}
	// The first entry is all zeros.
	var skip [elf.Sym32Size]byte
	symtab.Read(skip[:])
	symbols := make([]elf.Symbol, symtab.Len()/elf.Sym32Size)
	i := 0
	var sym elf.Sym32
	for symtab.Len() > 0 {
		binary.Read(symtab, f.ByteOrder, &sym)
		str, _ := getString(strdata, int(sym.Name))
		symbols[i].Name = str
		symbols[i].Info = sym.Info
		symbols[i].Other = sym.Other
		symbols[i].Section = elf.SectionIndex(sym.Shndx)
		symbols[i].Value = uint64(sym.Value)
		symbols[i].Size = uint64(sym.Size)
		i++
	}
	return symbols, strdata, nil
}

func getSymbols64(f *elf.File, typ elf.SectionType) ([]elf.Symbol, []byte, error) {
	symtabSection := f.SectionByType(typ)
	if symtabSection == nil {
		return nil, nil, elf.ErrNoSymbols
	}

	data, err := readElfSectionData(symtabSection) //symtabSection.Data()
	if err != nil {
		return nil, nil, errors.New("cannot load symbol section")
	}
	symtab := bytes.NewReader(data)
	if symtab.Len()%elf.Sym64Size != 0 {
		return nil, nil, errors.New("length of symbol section is not a multiple of Sym64Size")
	}
	strdata, err := stringTable(f, symtabSection.Link)
	if err != nil {
		return nil, nil, errors.New("cannot load string table section")
	}
	// The first entry is all zeros.
	var skip [elf.Sym64Size]byte
	symtab.Read(skip[:])
	symbols := make([]elf.Symbol, symtab.Len()/elf.Sym64Size)
	i := 0
	var sym elf.Sym64
	for symtab.Len() > 0 {
		binary.Read(symtab, f.ByteOrder, &sym)
		str, _ := getString(strdata, int(sym.Name))
		symbols[i].Name = str
		symbols[i].Info = sym.Info
		symbols[i].Other = sym.Other
		symbols[i].Section = elf.SectionIndex(sym.Shndx)
		symbols[i].Value = sym.Value
		symbols[i].Size = sym.Size
		i++
	}
	return symbols, strdata, nil
}

// getSymbols returns a slice of Symbols from parsing the symbol table
// with the given type, along with the associated string table.
func getSymbols(f *elf.File, typ elf.SectionType) ([]elf.Symbol, []byte, error) {
	switch f.Class {
	case elf.ELFCLASS64:
		return getSymbols64(f, typ)
	case elf.ELFCLASS32:
		return getSymbols32(f, typ)
	}
	return nil, nil, errors.New("not implemented")
}

func readElfSectionData(s *elf.Section) ([]byte, error) {
	dat := make([]byte, s.Size)
	n, err := s.ReaderAt.ReadAt(dat, 0)
	return dat[0:n], err
}

func readElfProgSectionData(s *elf.Prog) ([]byte, error) {
	dat := make([]byte, s.Memsz)
	n, err := s.ReaderAt.ReadAt(dat, 0)
	return dat[0:n], err
}

func SectionByTypeProg(f *elf.File, typ elf.ProgType) *elf.Prog {
	for _, s := range f.Progs {
		if s.Type == typ {
			return s
		}
	}
	return nil
}

// getDynamicTagValue() read the tag value from the Dynamic section, from ELF progs headers
func getDynamicTagValue(f *elf.File, tag elf.DynTag) (uint64, error) {
	ds := SectionByTypeProg(f, elf.PT_DYNAMIC)
	if ds == nil {
		// not dynamic, so no libraries
		return uint64(0), fmt.Errorf("no progs dynamic section")
	}

	d, err := readElfProgSectionData(ds)
	if err != nil {
		return uint64(0), err
	}

	for len(d) > 0 {
		var t elf.DynTag
		var v uint64
		switch f.Class {
		case elf.ELFCLASS32:
			t = elf.DynTag(f.ByteOrder.Uint32(d[0:4]))
			v = uint64(f.ByteOrder.Uint32(d[4:8]))
			d = d[8:]
		case elf.ELFCLASS64:
			t = elf.DynTag(f.ByteOrder.Uint64(d[0:8]))
			v = f.ByteOrder.Uint64(d[8:16])
			d = d[16:]
		}
		if t == tag {
			return v, nil
		}
	}
	return uint64(0), fmt.Errorf("tag not found")
}

func createSection(f *elf.File, r io.ReaderAt, sectionType elf.SectionType, addr uint64, size uint64) *elf.Section {
	s := new(elf.Section)
	switch f.Class {
	case elf.ELFCLASS32:
		s.SectionHeader = elf.SectionHeader{
			Type:      sectionType,
			Flags:     elf.SHF_ALLOC,
			Addr:      addr,
			Offset:    addr,
			FileSize:  size,
			Link:      0,
			Info:      0,
			Addralign: 4,
			Entsize:   0,
		}
	case elf.ELFCLASS64:
		s.SectionHeader = elf.SectionHeader{
			Type:      sectionType,
			Flags:     elf.SHF_ALLOC,
			Offset:    addr,
			FileSize:  size,
			Addr:      addr,
			Link:      0,
			Info:      0,
			Addralign: 8,
			Entsize:   0,
		}
	}
	reader := io.NewSectionReader(r, int64(s.Offset), int64(s.FileSize))
	s.ReaderAt = reader
	s.Size = s.FileSize
	return s
}

func rebuildSymtabStrTabFromDynamic(f *elf.File, r io.ReaderAt, vBaseAddr uintptr, mapSize uint64) error {
	addrSymtab, err := getDynamicTagValue(f, elf.DT_SYMTAB)
	if err != nil {
		return err
	}
	addrStrtab, err := getDynamicTagValue(f, elf.DT_STRTAB)
	if err != nil {
		return err
	}

	if addrStrtab-addrSymtab <= 0 {
		return fmt.Errorf("symtab and strtab are not in order")
	}
	if addrStrtab-addrSymtab != 0x2e8 {
		return fmt.Errorf("double check failed")
	}

	f.Sections = make([]*elf.Section, 2)
	f.Sections[0] = createSection(f, r, elf.SHT_DYNSYM, addrSymtab-uint64(vBaseAddr), addrStrtab-addrSymtab)
	f.Sections[0].Link = 1
	strtabOffset := addrStrtab - uint64(vBaseAddr)
	f.Sections[1] = createSection(f, r, elf.SHT_STRTAB, strtabOffset, mapSize-strtabOffset /* max available */)

	return nil
}

func NewFile(r io.ReaderAt, vBaseAddr uintptr, size int64) (*elf.File, error) {
	sr := io.NewSectionReader(r, 0, 1<<63-1)
	var err error
	var phoff int64
	var phentsize, phnum int
	var shoff int64
	var shentsize, shnum, shstrndx int
	f := new(elf.File)

	decodeELFIdentifier := func() error {
		// Read and decode ELF identifier
		var ident [16]uint8
		if _, err := r.ReadAt(ident[0:], 0); err != nil {
			return err
		}
		if ident[0] != '\x7f' || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {
			return &FormatError{0, "bad magic number", ident[0:4]}
		}

		f.Class = elf.Class(ident[elf.EI_CLASS])
		switch f.Class {
		case elf.ELFCLASS32:
		case elf.ELFCLASS64:
			// ok
		default:
			return &FormatError{0, "unknown ELF class", f.Class}
		}

		f.Data = elf.Data(ident[elf.EI_DATA])
		switch f.Data {
		case elf.ELFDATA2LSB:
			f.ByteOrder = binary.LittleEndian
		case elf.ELFDATA2MSB:
			f.ByteOrder = binary.BigEndian
		default:
			return &FormatError{0, "unknown ELF data encoding", f.Data}
		}

		f.Version = elf.Version(ident[elf.EI_VERSION])
		if f.Version != elf.EV_CURRENT {
			return &FormatError{0, "unknown ELF version", f.Version}
		}
		f.OSABI = elf.OSABI(ident[elf.EI_OSABI])
		f.ABIVersion = ident[elf.EI_ABIVERSION]
		return nil
	}

	readFileHeader := func() error {
		// Read ELF file header
		switch f.Class {

		case elf.ELFCLASS32:
			hdr := new(elf.Header32)
			sr.Seek(0, seekStart)
			if err := binary.Read(sr, f.ByteOrder, hdr); err != nil {
				return err
			}
			f.Type = elf.Type(hdr.Type)
			f.Machine = elf.Machine(hdr.Machine)
			f.Entry = uint64(hdr.Entry)
			if v := elf.Version(hdr.Version); v != f.Version {
				return &FormatError{0, "mismatched ELF version", v}
			}
			phoff = int64(hdr.Phoff)
			phentsize = int(hdr.Phentsize)
			phnum = int(hdr.Phnum)
			shoff = int64(hdr.Shoff)
			shentsize = int(hdr.Shentsize)
			shnum = int(hdr.Shnum)
			shstrndx = int(hdr.Shstrndx)

		case elf.ELFCLASS64:
			hdr := new(elf.Header64)
			sr.Seek(0, seekStart)
			if err := binary.Read(sr, f.ByteOrder, hdr); err != nil {
				return err
			}
			f.Type = elf.Type(hdr.Type)
			f.Machine = elf.Machine(hdr.Machine)
			f.Entry = hdr.Entry
			if v := elf.Version(hdr.Version); v != f.Version {
				return &FormatError{0, "mismatched ELF version", v}
			}
			phoff = int64(hdr.Phoff)
			phentsize = int(hdr.Phentsize)
			phnum = int(hdr.Phnum)
			shoff = int64(hdr.Shoff)
			shentsize = int(hdr.Shentsize)
			shnum = int(hdr.Shnum)
			shstrndx = int(hdr.Shstrndx)
		}

		if shoff == 0 && shnum != 0 {
			return &FormatError{0, "invalid ELF shnum for shoff=0", shnum}
		}
		if shnum > 0 && shstrndx >= shnum {
			return &FormatError{0, "invalid ELF shstrndx", shstrndx}
		}
		return nil
	}

	readProgramHeaders := func() error {
		// Read program headers
		f.Progs = make([]*elf.Prog, phnum)
		for i := 0; i < phnum; i++ {
			off := phoff + int64(i)*int64(phentsize)
			sr.Seek(off, seekStart)
			p := new(elf.Prog)
			switch f.Class {
			case elf.ELFCLASS32:
				ph := new(elf.Prog32)
				if err := binary.Read(sr, f.ByteOrder, ph); err != nil {
					return err
				}
				p.ProgHeader = elf.ProgHeader{
					Type:   elf.ProgType(ph.Type),
					Flags:  elf.ProgFlag(ph.Flags),
					Off:    uint64(ph.Off),
					Vaddr:  uint64(ph.Vaddr),
					Paddr:  uint64(ph.Paddr),
					Filesz: uint64(ph.Filesz),
					Memsz:  uint64(ph.Memsz),
					Align:  uint64(ph.Align),
				}
			case elf.ELFCLASS64:
				ph := new(elf.Prog64)
				if err := binary.Read(sr, f.ByteOrder, ph); err != nil {
					return err
				}
				p.ProgHeader = elf.ProgHeader{
					Type:   elf.ProgType(ph.Type),
					Flags:  elf.ProgFlag(ph.Flags),
					Off:    ph.Off,
					Vaddr:  ph.Vaddr,
					Paddr:  ph.Paddr,
					Filesz: ph.Filesz,
					Memsz:  ph.Memsz,
					Align:  ph.Align,
				}
			}
			p.ReaderAt = io.NewSectionReader(r, int64(p.Off), int64(p.Filesz))
			f.Progs[i] = p
		}
		return nil
	}

	readSectionHeaders := func() error {
		// Read section headers
		f.Sections = make([]*elf.Section, shnum)
		names := make([]uint32, shnum)
		for i := 0; i < shnum; i++ {
			off := shoff + int64(i)*int64(shentsize)
			sr.Seek(off, seekStart)
			s := new(elf.Section)
			switch f.Class {
			case elf.ELFCLASS32:
				sh := new(elf.Section32)
				if err := binary.Read(sr, f.ByteOrder, sh); err != nil {
					return err
				}
				names[i] = sh.Name
				s.SectionHeader = elf.SectionHeader{
					Type:      elf.SectionType(sh.Type),
					Flags:     elf.SectionFlag(sh.Flags),
					Addr:      uint64(sh.Addr),
					Offset:    uint64(sh.Off),
					FileSize:  uint64(sh.Size),
					Link:      sh.Link,
					Info:      sh.Info,
					Addralign: uint64(sh.Addralign),
					Entsize:   uint64(sh.Entsize),
				}
			case elf.ELFCLASS64:
				sh := new(elf.Section64)
				if err := binary.Read(sr, f.ByteOrder, sh); err != nil {
					return err
				}
				names[i] = sh.Name
				s.SectionHeader = elf.SectionHeader{
					Type:      elf.SectionType(sh.Type),
					Flags:     elf.SectionFlag(sh.Flags),
					Offset:    sh.Off,
					FileSize:  sh.Size,
					Addr:      sh.Addr,
					Link:      sh.Link,
					Info:      sh.Info,
					Addralign: sh.Addralign,
					Entsize:   sh.Entsize,
				}
			}
			reader := io.NewSectionReader(r, int64(s.Offset), int64(s.FileSize))
			if s.Flags&elf.SHF_COMPRESSED == 0 {
				s.ReaderAt = reader
				s.Size = s.FileSize
			} else {
				//
				/* We don't need parsing compression as it's already loaded in memory */
				//
				return &FormatError{0, "Compresson unsupported", s.Flags}
			}
			f.Sections[i] = s
		}
		return nil
	}

	/* read ELF ... */
	if err := decodeELFIdentifier(); err != nil {
		return nil, err
	}
	if err := readFileHeader(); err != nil {
		return nil, err
	}
	if err := readProgramHeaders(); err != nil {
		return nil, err
	}
	err = readSectionHeaders()
	if err != nil {
		if err == io.EOF {
			// Read Section failed most probably because the ELF section headers are not mapped in memory
			// Try to rebuild/recover the dynamic symbol table from the PT_DYNAMIC prog section
			if err = rebuildSymtabStrTabFromDynamic(f, r, vBaseAddr, uint64(size)); err != nil {
				return nil, err
			}
			/* Only dynamic sym/str tab are avaiable */
			return f, nil
		}
	}

	if len(f.Sections) == 0 {
		return f, nil
	}

	sectionsSanityCheck := func() error {
		// Load section header string table as sanity check/test.
		_, err = readElfSectionData(f.Sections[shstrndx])
		if err != nil {
			return err
		}
		//
		/* We don't check section name as not all are available */
		//
		return nil
	}
	if err := sectionsSanityCheck(); err != nil {
		return nil, err
	}

	return f, nil
}
