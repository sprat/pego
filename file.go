package pego

import (
	"errors"
	"io"
)

// Represents a PE file structure
type PE struct {
	DosHeader *Header[DosHeader]
	DosStub   *Segment
	PEHeader  *Header[PEHeader]
}

// NewPE creates a PE instance
func NewPE(reader io.ReaderAt) (*PE, error) {
	offset := int64(0)

	// Dos Header
	dosHeader, err := NewHeader[DosHeader](reader, &offset)
	if err != nil {
		return nil, err
	}

	if dosHeader.Data.Magic != 0x5a4d {
		return nil, errors.New("invalid DOS Header Signature")
	}

	// Dos Stub
	peHeaderOffset := int64(dosHeader.Data.Lfanew)
	dosStubSize := peHeaderOffset - offset
	dosStub := NewSegment(reader, &offset, dosStubSize)

	// PE Header
	peHeader, err := NewHeader[PEHeader](reader, &offset)
	if err != nil {
		return nil, err
	}
	if peHeader.Data.Magic != 0x00004550 {
		return nil, errors.New("invalid PE Header Signature")
	}

	return &PE{
		DosHeader: dosHeader,
		DosStub:   dosStub,
		PEHeader:  peHeader,
	}, nil
}
