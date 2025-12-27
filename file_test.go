package pego

import (
	"debug/pe"
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func TestFileReadExe(t *testing.T) {
	file, err := os.Open(filepath.Join("testfiles", "piano.exe"))
	assert.NilError(t, err)
	defer file.Close()

	peFile, err := NewPE(file)
	assert.NilError(t, err)

	// DOS Header
	assert.Equal(t, peFile.DOSHeader.Size(), int64(64))
	assert.Equal(t, peFile.DOSHeader.Data.Lfanew, uint32(64+128))

	// DOS Stub
	assert.Equal(t, peFile.DOSStub.Size(), int64(128))

	// PE Signature
	assert.Assert(t, peFile.PESignature != nil)

	// COFF Header
	assert.Equal(t, peFile.COFFHeader.Size(), int64(20))
	assert.Equal(t, peFile.COFFHeader.Data.Machine, uint16(pe.IMAGE_FILE_MACHINE_I386))
	assert.Equal(t, peFile.COFFHeader.Data.NumberOfSections, uint16(3))
	assert.Equal(t, peFile.COFFHeader.Data.SizeOfOptionalHeader, uint16(224))
}

func TestFileReadObj(t *testing.T) {
	file, err := os.Open(filepath.Join("testfiles", "sample.obj"))
	assert.NilError(t, err)
	defer file.Close()

	peFile, err := NewPE(file)
	assert.NilError(t, err)

	// DOS Header, DOS Stub and PE Signature should not by present
	assert.Assert(t, peFile.DOSHeader == nil)
	assert.Assert(t, peFile.DOSStub == nil)
	assert.Assert(t, peFile.PESignature == nil)

	// COFF Header
	assert.Equal(t, peFile.COFFHeader.Size(), int64(20))
	assert.Equal(t, peFile.COFFHeader.Data.Machine, uint16(pe.IMAGE_FILE_MACHINE_AMD64))
	assert.Equal(t, peFile.COFFHeader.Data.NumberOfSections, uint16(6))
	assert.Equal(t, peFile.COFFHeader.Data.SizeOfOptionalHeader, uint16(0))
}
