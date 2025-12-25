package pego

import (
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func TestFileRead(t *testing.T) {
	f, err := os.Open(filepath.Join("testfiles", "piano.exe"))
	if err != nil {
		t.Fatal("Cannot open test file")
	}
	defer f.Close()

	pe, err := NewPE(f)
	if err != nil {
		t.Fatal(err)
	}

	dosHeaderData := pe.DosHeader.Data
	assert.Equal(t, dosHeaderData.Lfanew, uint32(0xc0))
}
