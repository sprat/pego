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
}

func TestFile268Exe(t *testing.T) {
	// 268.exe is a minimal 268-byte EXE where the PE structure starts inside the DOS header
	// area (Lfanew = 4). This is a degenerate but valid technique used by size-optimized executables.
	p, err := NewPE(openTestFile(t, "268.exe"))
	assert.NilError(t, err)

	// DOS Header.
	assert.Assert(t, p.DOSHeader != nil)
	assert.Equal(t, p.DOSHeader.Lfanew, uint32(0x04))

	// No DOS stub since Lfanew points inside the DOS header.
	assert.Assert(t, p.DOSStub == nil)

	// PE Signature.
	assert.Assert(t, p.PESignature != nil)

	// COFF Header.
	assert.Equal(t, p.COFFHeader.Machine, uint16(pe.IMAGE_FILE_MACHINE_AMD64))
	assert.Equal(t, p.COFFHeader.NumberOfSections, uint16(1))

	// Optional Header (PE32+).
	assert.Assert(t, p.OptionalHeader64 != nil)
	assert.Assert(t, p.OptionalHeader32 == nil)
}

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
