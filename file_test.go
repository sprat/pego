package pego

import (
	"debug/pe"
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func TestFileRead(t *testing.T) {
	file, err := os.Open(filepath.Join("testfiles", "piano.exe"))
	assert.NilError(t, err, "Cannot open test file")
	defer file.Close()

	peFile, err := NewPE(file)
	assert.NilError(t, err, "Cannot parse PE file")

	// DosHeader
	assert.Equal(t, peFile.DosHeader.Size(), int64(64))
	assert.Equal(t, peFile.DosHeader.Data.Lfanew, uint32(64+128))

	// DosStub
	assert.Equal(t, peFile.DosStub.Size(), int64(128))

	// PEHeader
	assert.Equal(t, peFile.PEHeader.Size(), int64(24))
	assert.Equal(t, peFile.PEHeader.Data.Machine, uint16(pe.IMAGE_FILE_MACHINE_I386))
	assert.Equal(t, peFile.PEHeader.Data.NumberOfSections, uint16(3))
	assert.Equal(t, peFile.PEHeader.Data.SizeOfOptionalHeader, uint16(224))
}
