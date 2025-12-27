package pego

import (
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func TestFileRead(t *testing.T) {
	f, err := os.Open(filepath.Join("testfiles", "piano.exe"))
	assert.NilError(t, err, "Cannot open test file")
	defer f.Close()

	pe, err := NewPE(f)
	assert.NilError(t, err, "Invalid PE file")

	// DosHeader
	assert.Equal(t, pe.DosHeader.Size(), int64(0x40))
	assert.Equal(t, pe.DosHeader.Data.Lfanew, uint32(0xc0))
}
