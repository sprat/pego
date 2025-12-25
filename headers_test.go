package pego

import (
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func TestHeader(t *testing.T) {
	f, err := os.Open(filepath.Join("testfiles", "piano.exe"))
	if err != nil {
		t.Fatal("Cannot open test file")
	}
	defer f.Close()

	offset := int64(0)
	header := NewHeader[DosHeader](f, &offset)

	assert.Equal(t, offset, int64(64))
	assert.Equal(t, header.Data.Magic, uint16(0x5a4d))
	assert.Equal(t, header.Data.Lfanew, uint32(0xc0))
}
