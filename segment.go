package pego

import "io"

type Segment struct {
	reader *io.SectionReader
}

func NewSegment(reader io.ReaderAt, offset *int64, size int64) *Segment {
	r := io.NewSectionReader(reader, *offset, size)
	*offset += size
	return &Segment{
		reader: r,
	}
}

func (s *Segment) Write(writer io.Writer) error {
	_, err := io.Copy(writer, s.reader)
	s.reader.Seek(0, io.SeekStart)
	return err
}
