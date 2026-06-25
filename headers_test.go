package pego

import (
	"bytes"
	"io"
	"testing"

	"gotest.tools/v3/assert"
)

func TestHeaderValid(t *testing.T) {
	reader := openTestFile(t, "piano.exe")
	offset := int64(0)

	header, err := readHeader[DOSHeader](reader, &offset)
	assert.NilError(t, err)

	// The offset is increased.
	assert.Equal(t, offset, int64(64))

	// We read the data correctly.
	assert.Equal(t, header.Magic, uint16(DOSHeaderMagic))
	assert.Equal(t, header.Lfanew, uint32(0xc0))

	// We can write the data to a buffer.
	var buffer bytes.Buffer
	assert.NilError(t, writeHeader(&buffer, header))
	assert.Equal(t, buffer.Len(), 64)
	assert.Equal(t, buffer.Bytes()[0], byte(0x4d))
	assert.Equal(t, buffer.Bytes()[1], byte(0x5a))

	// We can write the data again.
	buffer.Reset()
	assert.NilError(t, writeHeader(&buffer, header))
	assert.Equal(t, buffer.Len(), 64)
}

func TestHeaderUnexpectedEOF(t *testing.T) {
	data := []byte{0x11, 0x22, 0x33, 0x44}
	reader := bytes.NewReader(data)
	offset := int64(0)
	header, err := readHeader[DOSHeader](reader, &offset)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Assert(t, header == nil)
	assert.Equal(t, offset, int64(0))
}
