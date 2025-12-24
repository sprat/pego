package pego

import (
	"errors"
	"io"
)

// Represents a PE file structure
type PE struct {
	DosHeader *Header[DosHeader]
}

// NewPE creates a PE instance
func NewPE(reader io.ReaderAt) (*PE, error) {
	offset := int64(0)

	// Dos Header
	dosHeader := NewHeader[DosHeader](reader, &offset)
	if dosHeader.Data.Magic != 0x5a4d {
		return nil, errors.New("Invalid DOS Header Magic")
	}

	return &PE{
		DosHeader: dosHeader,
	}, nil
}
