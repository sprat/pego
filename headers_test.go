package pego

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func TestHeaderValid(t *testing.T) {
	f, err := os.Open(filepath.Join("testfiles", "piano.exe"))
	assert.NilError(t, err)
	defer f.Close()

	offset := int64(0)
	header, err := NewHeader[DosHeader](f, &offset)

	// the size is correct
	assert.Equal(t, header.Size(), int64(64))

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

func TestHeaderUnexpectedEOF(t *testing.T) {
	var data []byte = []byte{0x11, 0x22, 0x33, 0x44}
	reader := bytes.NewReader(data)
	offset := int64(0)
	header, err := NewHeader[DosHeader](reader, &offset)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Assert(t, header == nil)
	assert.Equal(t, offset, int64(0))
}
