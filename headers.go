package pego

import (
	"encoding/binary"
	"io"
)

// readHeader reads a header of type T from reader at the given offset, advancing the offset by the size of the header.
// Returns a pointer to the newly read header or an error if reading failed.
func readHeader[T any](reader io.ReaderAt, offset *int64) (*T, error) {
	h := new(T)
	size := int64(binary.Size(h))
	r := io.NewSectionReader(reader, *offset, size)
	err := binary.Read(r, binary.LittleEndian, h)
	if err != nil {
		return nil, err
	}
	*offset += size
	return h, nil
}

// writeHeader serializes the header data to the writer in little-endian byte order.
func writeHeader(writer io.Writer, h any) error {
	return binary.Write(writer, binary.LittleEndian, h)
}

// DOSHeader contains the DOS header data.
type DOSHeader struct {
	Magic    uint16     // Magic number.
	Cblp     uint16     // Bytes on last page of file.
	Cp       uint16     // Pages in file.
	Crlc     uint16     // Relocations.
	Cparhdr  uint16     // Size of header in paragraphs.
	Minalloc uint16     // Minimum extra paragraphs needed.
	Maxalloc uint16     // Maximum extra paragraphs needed.
	Ss       uint16     // Initial (relative) SS value.
	Sp       uint16     // Initial SP value.
	Csum     uint16     // Checksum.
	Ip       uint16     // Initial IP value.
	Cs       uint16     // Initial (relative) CS value.
	Lfarlc   uint16     // File address of relocation table.
	Ovno     uint16     // Overlay number.
	Res      [4]uint16  // Reserved uint16s.
	Oemid    uint16     // OEM identifier (for e_oeminfo).
	Oeminfo  uint16     // OEM information; e_oemid specific.
	Res2     [10]uint16 // Reserved uint16s.
	Lfanew   uint32     // File address of new exe header.
}

// PESignature is the PE file signature type.
type PESignature uint32

// OptionalHeader32 contains the PE32 optional header fields, excluding data directories.
type OptionalHeader32 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

// OptionalHeader64 contains the PE32+ optional header fields, excluding data directories.
type OptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

const (
	DOSHeaderMagic   uint16      = 0x5a4d     // 'M', 'Z'
	PESignatureMagic PESignature = 0x00004550 // 'P', 'E', 0, 0
	PE32Magic                    = 0x10b
	PE32PlusMagic                = 0x20b
)
