package pego

import (
	"debug/pe"
	"encoding/binary"
	"io"
)

// Header wraps a PE header data structure.
type Header[T any] struct {
	Data T
}

// NewHeader reads a header of type T from reader at the given offset, advances the offset by the size of T, and returns the header.
func NewHeader[T any](reader io.ReaderAt, offset *int64) (*Header[T], error) {
	h := Header[T]{}
	size := h.Size()
	r := io.NewSectionReader(reader, *offset, size)
	err := binary.Read(r, binary.LittleEndian, &h.Data)
	if err != nil {
		return nil, err
	}
	*offset += size
	return &h, nil
}

// Size returns the size of the header data in bytes.
func (h *Header[T]) Size() int64 {
	return int64(binary.Size(h.Data))
}

// Write serializes the header data to the writer in little-endian byte order.
func (h *Header[T]) Write(writer io.Writer) error {
	return binary.Write(writer, binary.LittleEndian, h.Data)
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

// COFFHeader contains the COFF file header data.
type COFFHeader pe.FileHeader

// OptionalHeader32 contains the PE32 optional header data.
type OptionalHeader32 pe.OptionalHeader32

// OptionalHeader64 contains the PE32+ optional header data.
type OptionalHeader64 pe.OptionalHeader64

const (
	DOSHeaderMagic               = 0x5a4d
	PESignatureMagic PESignature = 0x00004550 // 'P', 'E', 0, 0
	PE32Magic                    = 0x10b
	PE32PlusMagic                = 0x20b
)
