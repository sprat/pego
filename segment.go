package pego

import "io"

type Segment struct {
	reader *io.SectionReader
}

func NewSegment(reader io.ReaderAt, offset *int64, size int64) *Segment {
	r := io.NewSectionReader(reader, *offset, size)
	*offset += size
	return &Segment{reader: r}
}

func (s *Segment) Size() int64 {
	return s.reader.Size()
}

func (s *Segment) Write(writer io.Writer) error {
	// Make a copy of the section reader so that we don't change the offset.
	_, err := io.Copy(writer, io.NewSectionReader(s.reader, 0, s.reader.Size()))
	return err
}
