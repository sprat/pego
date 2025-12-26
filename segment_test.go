package pego

import (
	"bytes"
	"testing"

	"gotest.tools/v3/assert"
)

func TestSegment(t *testing.T) {
	data := []byte{0x11, 0x22, 0x33, 0x44}
	reader := bytes.NewReader(data)

	offset := int64(0)
	segment := NewSegment(reader, &offset, 4)

	// the size is correct
	assert.Equal(t, segment.Size(), int64(4))

	// the offset is increased
	assert.Equal(t, offset, int64(4))

	// we can write the data to a buffer
	var buffer bytes.Buffer
	segment.Write(&buffer)
	assert.Equal(t, buffer.Len(), 4)
	assert.Equal(t, buffer.Bytes()[0], byte(0x11))
	assert.Equal(t, buffer.Bytes()[1], byte(0x22))

	// we can write the data again
	buffer.Reset()
	segment.Write(&buffer)
	assert.Equal(t, buffer.Len(), 4)
}
