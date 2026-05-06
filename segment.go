package pego

import "io"

// Segment represents a contiguous region of bytes within a PE file.
type Segment struct {
	reader *io.SectionReader
}

// NewSegment creates a Segment of the given size at the current offset and advances the offset.
func NewSegment(reader io.ReaderAt, offset *int64, size int64) *Segment {
	r := io.NewSectionReader(reader, *offset, size)
	*offset += size
	return &Segment{reader: r}
}

// Size returns the size of the segment in bytes.
func (s *Segment) Size() int64 {
	return s.reader.Size()
}

// Write copies the segment data to the writer.
func (s *Segment) Write(writer io.Writer) error {
	// Make a copy of the section reader so that we don't change the offset.
	_, err := io.Copy(writer, io.NewSectionReader(s.reader, 0, s.reader.Size()))
	return err
}
