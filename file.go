package pego

import (
	"debug/pe"
	"errors"
	"io"
)

// Represents a PE file structure
type PE struct {
	DOSHeader   *Header[DOSHeader]
	DOSStub     *Segment
	PESignature *Header[PESignature]
	COFFHeader  *Header[pe.FileHeader]
}

// NewPE creates a PE instance
func NewPE(reader io.ReaderAt) (*PE, error) {
	offset := int64(0)

	// DOS Header
	dosHeader, err := NewHeader[DOSHeader](reader, &offset)
	if err != nil {
		return nil, err
	}
	if dosHeader.Data.Magic != 0x5a4d {
		return nil, errors.New("invalid DOS Header Signature")
	}

	// DOS Stub
	peHeaderOffset := int64(dosHeader.Data.Lfanew)
	dosStubSize := peHeaderOffset - offset
	dosStub := NewSegment(reader, &offset, dosStubSize)

	// PE Signature
	peSignature, err := NewHeader[PESignature](reader, &offset)
	if err != nil {
		return nil, err
	}
	if peSignature.Data != 0x00004550 {
		return nil, errors.New("invalid PE Signature")
	}

	// COFF Header
	coffHeader, err := NewHeader[pe.FileHeader](reader, &offset)
	if err != nil {
		return nil, err
	}

	return &PE{
		DOSHeader:   dosHeader,
		DOSStub:     dosStub,
		PESignature: peSignature,
		COFFHeader:  coffHeader,
	}, nil
}
