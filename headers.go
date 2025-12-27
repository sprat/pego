package pego

import (
	"debug/pe"
	"encoding/binary"
	"io"
)

// Header
type Header[T any] struct {
	Data T
}

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

func (h *Header[T]) Size() int64 {
	return getStructSize[T]()
}

func (h *Header[T]) Write(writer io.Writer) error {
	return binary.Write(writer, binary.LittleEndian, h.Data)
}

// Dos Header data
type DosHeader struct {
	Magic    uint16     // Magic number
	Cblp     uint16     // Bytes on last page of file
	Cp       uint16     // Pages in file
	Crlc     uint16     // Relocations
	Cparhdr  uint16     // Size of header in paragraphs
	Minalloc uint16     // Minimum extra paragraphs needed
	Maxalloc uint16     // Maximum extra paragraphs needed
	Ss       uint16     // Initial (relative) SS value
	Sp       uint16     // Initial SP value
	Csum     uint16     // Checksum
	Ip       uint16     // Initial IP value
	Cs       uint16     // Initial (relative) CS value
	Lfarlc   uint16     // File address of relocation table
	Ovno     uint16     // Overlay number
	Res      [4]uint16  // Reserved uint16s
	Oemid    uint16     // OEM identifier (for e_oeminfo)
	Oeminfo  uint16     // OEM information; e_oemid specific
	Res2     [10]uint16 // Reserved uint16s
	Lfanew   uint32     // File address of new exe header
}

type PEHeader struct {
	Magic uint32 // Magic number
	pe.FileHeader
}
