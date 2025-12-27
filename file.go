package pego

import (
	"errors"
	"io"
)

// Represents a PE file structure
type PE struct {
	DosHeader *Header[DosHeader]
	DosStub   *Segment
}

// NewPE creates a PE instance
func NewPE(reader io.ReaderAt) (*PE, error) {
	offset := int64(0)

	// Dos Header
	dosHeader := NewHeader[DosHeader](reader, &offset)
	if dosHeader.Data.Magic != 0x5a4d {
		return nil, errors.New("invalid DOS Header Signature")
	}

	// Dos Stub
	peHeaderOffset := int64(dosHeader.Data.Lfanew)
	dosStubSize := peHeaderOffset - offset
	dosStub := NewSegment(reader, &offset, dosStubSize)

	return &PE{
		DosHeader: dosHeader,
		DosStub:   dosStub,
	}, nil
}
