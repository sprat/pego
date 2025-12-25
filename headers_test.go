package pego

import (
	"bytes"
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

	// the offset is increased
	assert.Equal(t, offset, int64(64))

	// we read the data correctly
	assert.Equal(t, header.Data.Magic, uint16(0x5a4d))
	assert.Equal(t, header.Data.Lfanew, uint32(0xc0))

	// we can write the data to a buffer
	var buffer bytes.Buffer
	header.Write(&buffer)
	assert.Equal(t, buffer.Len(), 64)
	assert.Equal(t, buffer.Bytes()[0], byte(0x4d))
	assert.Equal(t, buffer.Bytes()[1], byte(0x5a))

	// we can write the data again
	buffer.Reset()
	header.Write(&buffer)
	assert.Equal(t, buffer.Len(), 64)
}
