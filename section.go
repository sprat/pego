package pego

import (
	"debug/pe"
	"io"
)

type Section struct {
	Header *pe.SectionHeader32
	Segment *Segment
}

func NewSection(reader io.ReaderAt, offset *int64) (*Section, error) {
	// read the header
	header, err := readHeader[pe.SectionHeader32](reader, offset)
	if err != nil {
		return nil, err
	}

	// create the segment
	segmentOffset := int64(header.PointerToRawData)
	segmentSize := int64(header.SizeOfRawData)
	segment := NewSegment(reader, &segmentOffset, segmentSize)

	return &Section{
		Header: header,
		Segment: segment,
	}, nil
}

func (s *Section) Name() string {
	// TODO: it seems there's another case to support
	return cstring(s.Header.Name[:])
}
