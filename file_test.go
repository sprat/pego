package pego

import (
	"debug/pe"
	"io"
	"testing"

	"gotest.tools/v3/assert"
)

func TestFilePianoExe(t *testing.T) {
	p, err := NewPE(openTestFile(t, "piano.exe"))
	assert.NilError(t, err)

	// DOS Header.
	assert.Equal(t, p.DOSHeader.Lfanew, uint32(0xc0))

	// DOS Stub.
	assert.Equal(t, p.DOSStub.Size(), int64(0x80))

	// PE Signature.
	assert.Assert(t, p.PESignature != nil)

	// COFF Header.
	assert.Equal(t, p.COFFHeader.Machine, uint16(pe.IMAGE_FILE_MACHINE_I386))
	assert.Equal(t, p.COFFHeader.NumberOfSections, uint16(3))
	assert.Equal(t, p.COFFHeader.SizeOfOptionalHeader, uint16(0xe0))

	// Optional Header.
	assert.Equal(t, p.OptionalHeader32.SizeOfCode, uint32(0x340))
	assert.Equal(t, p.OptionalHeader32.SizeOfInitializedData, uint32(0xc0))
	assert.Equal(t, p.OptionalHeader32.SizeOfUninitializedData, uint32(0))
	assert.Equal(t, p.OptionalHeader32.FileAlignment, uint32(0x10))
	assert.Equal(t, p.OptionalHeader32.SectionAlignment, uint32(0x10))
	assert.Equal(t, p.OptionalHeader32.SizeOfImage, uint32(0x630))
	assert.Equal(t, p.OptionalHeader32.SizeOfHeaders, uint32(0x230))
	assert.Assert(t, p.OptionalHeader64 == nil)

	// Sections
	assert.Equal(t, len(p.Sections), 3)
	s0 := p.Sections[0]
	assert.Equal(t, s0.Name(), ".")
	assert.Equal(t, s0.Header.VirtualSize, uint32(0x33c))
	assert.Equal(t, s0.Header.VirtualAddress, uint32(0x230))
	assert.Equal(t, s0.Segment.Size(), int64(0x340))

	s1 := p.Sections[1]
	assert.Equal(t, s1.Name(), ".data")
	assert.Equal(t, s1.Header.VirtualSize, uint32(0x6a))
	assert.Equal(t, s1.Header.VirtualAddress, uint32(0x570))
	assert.Equal(t, s1.Segment.Size(), int64(0x70))

	s2 := p.Sections[2]
	assert.Equal(t, s2.Name(), ".reloc")
	assert.Equal(t, s2.Header.VirtualSize, uint32(0x4c))
	assert.Equal(t, s2.Header.VirtualAddress, uint32(0x5e0))
	assert.Equal(t, s2.Segment.Size(), int64(0x50))
}

// TestFileReadTruncated verifies that NewPE returns an error when the input is truncated at various points.
func TestFileReadTruncated(t *testing.T) {
	tests := []struct {
		name string
		size int64
	}{
		{"PESignature", 0xc1},
		{"COFFHeader", 0xc8},
		{"OptionalHeaderMagic", 0xd8},
		{"OptionalHeader", 0xda},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := io.NewSectionReader(openTestFile(t, "piano.exe"), 0, tt.size)
			_, err := NewPE(reader)
			assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
		})
	}
}

func TestFileReadObj(t *testing.T) {
	p, err := NewPE(openTestFile(t, "sample.obj"))
	assert.NilError(t, err)

	// DOS Header, DOS Stub and PE Signature should not be present.
	assert.Assert(t, p.DOSHeader == nil)
	assert.Assert(t, p.DOSStub == nil)
	assert.Assert(t, p.PESignature == nil)

	// COFF Header.
	assert.Equal(t, p.COFFHeader.Machine, uint16(pe.IMAGE_FILE_MACHINE_AMD64))
	assert.Equal(t, p.COFFHeader.NumberOfSections, uint16(6))
	assert.Equal(t, p.COFFHeader.SizeOfOptionalHeader, uint16(0))

	// Optional Header.
	assert.Assert(t, p.OptionalHeader32 == nil)
	assert.Assert(t, p.OptionalHeader64 == nil)
}
