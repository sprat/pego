package pego

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

// PE represents a Portable Executable file structure.
type PE struct {
	DOSHeader        *DOSHeader
	DOSStub          *Segment
	PESignature      *PESignature
	COFFHeader       *pe.FileHeader
	OptionalHeader32 *OptionalHeader32
	OptionalHeader64 *OptionalHeader64
	DataDirectories  []pe.DataDirectory
}

// NewPE parses a Portable Executable or plain COFF file from reader.
// It supports both PE files (with a DOS header) and plain COFF object files.
// Returns an error if the input is malformed or truncated.
func NewPE(reader io.ReaderAt) (*PE, error) {
	p := PE{}
	offset := int64(0)

	// DOS Header.
	dosHeader, err := readHeader[DOSHeader](reader, &offset)
	if err == nil && dosHeader.Magic == DOSHeaderMagic {
		p.DOSHeader = dosHeader

		// DOS Stub.
		peHeaderOffset := int64(dosHeader.Lfanew)
		dosStubSize := peHeaderOffset - offset
		if dosStubSize > 0 {
			p.DOSStub = NewSegment(reader, &offset, dosStubSize)
		} else {
			// Degenerate case: Lfanew points before or at the end of the DOS header.
			offset = peHeaderOffset
		}

		// PE Signature.
		p.PESignature, err = readHeader[PESignature](reader, &offset)
		if err != nil {
			return nil, err
		}
		if *p.PESignature != PESignatureMagic {
			return nil, fmt.Errorf("invalid PE file signature: %#x", *p.PESignature)
		}
	} else {
		// Not a PE file with a DOS header, treat as a plain COFF file.
		// It will fail later if the COFF header is not valid.
		offset = 0
	}

	// COFF Header.
	p.COFFHeader, err = readHeader[pe.FileHeader](reader, &offset)
	if err != nil {
		return nil, err
	}

	// Make sure the machine type is valid.
	if !isValidMachine(p.COFFHeader.Machine) {
		return nil, fmt.Errorf("unrecognized PE machine: %#x", p.COFFHeader.Machine)
	}

	// Optional Header.
	optionalHeaderSize := p.COFFHeader.SizeOfOptionalHeader
	if optionalHeaderSize > 0 {
		var magicBytes [2]byte
		var numDirs uint32
		var baseSize int64

		// Read the magic number to determine if it's PE32 or PE32+.
		_, err = reader.ReadAt(magicBytes[:], offset)
		if err != nil {
			return nil, io.ErrUnexpectedEOF
		}

		magic := binary.LittleEndian.Uint16(magicBytes[:])
		switch magic {
		case PE32Magic:
			p.OptionalHeader32, err = readHeader[OptionalHeader32](reader, &offset)
			if err == nil {
				numDirs = p.OptionalHeader32.NumberOfRvaAndSizes
				baseSize = int64(binary.Size(p.OptionalHeader32))
			}
		case PE32PlusMagic:
			p.OptionalHeader64, err = readHeader[OptionalHeader64](reader, &offset)
			if err == nil {
				numDirs = p.OptionalHeader64.NumberOfRvaAndSizes
				baseSize = int64(binary.Size(p.OptionalHeader64))
			}
		default:
			err = fmt.Errorf("invalid optional header magic: %#x", magic)
		}

		if err != nil {
			return nil, err
		}

		p.DataDirectories, err = parseDataDirectories(reader, &offset, numDirs, int64(optionalHeaderSize), baseSize)
		if err != nil {
			return nil, err
		}

		/*
			TODO: repair this
			if optionalHeaderSize != expectedSize {
				return nil, fmt.Errorf("optional header size does not match the expected size: %#x != %#x", optionalHeaderSize, expectedSize)
			}
		*/
	}

	// TODO: add protections to defend against malicious files (e.g. oversized segments...)

	return &p, nil
}

// isValidMachine reports whether the given machine type is a known PE machine value.
func isValidMachine(machine uint16) bool {
	// TODO: technically it's ok, but should we restrict to the supported architectures in Golang like debug/pe?
	switch machine {
	case pe.IMAGE_FILE_MACHINE_UNKNOWN,
		pe.IMAGE_FILE_MACHINE_AM33,
		pe.IMAGE_FILE_MACHINE_AMD64,
		pe.IMAGE_FILE_MACHINE_ARM,
		pe.IMAGE_FILE_MACHINE_ARMNT,
		pe.IMAGE_FILE_MACHINE_ARM64,
		pe.IMAGE_FILE_MACHINE_EBC,
		pe.IMAGE_FILE_MACHINE_I386,
		pe.IMAGE_FILE_MACHINE_IA64,
		pe.IMAGE_FILE_MACHINE_LOONGARCH32,
		pe.IMAGE_FILE_MACHINE_LOONGARCH64,
		pe.IMAGE_FILE_MACHINE_M32R,
		pe.IMAGE_FILE_MACHINE_MIPS16,
		pe.IMAGE_FILE_MACHINE_MIPSFPU,
		pe.IMAGE_FILE_MACHINE_MIPSFPU16,
		pe.IMAGE_FILE_MACHINE_POWERPC,
		pe.IMAGE_FILE_MACHINE_POWERPCFP,
		pe.IMAGE_FILE_MACHINE_R4000,
		pe.IMAGE_FILE_MACHINE_SH3,
		pe.IMAGE_FILE_MACHINE_SH3DSP,
		pe.IMAGE_FILE_MACHINE_SH4,
		pe.IMAGE_FILE_MACHINE_SH5,
		pe.IMAGE_FILE_MACHINE_THUMB,
		pe.IMAGE_FILE_MACHINE_WCEMIPSV2,
		pe.IMAGE_FILE_MACHINE_RISCV32,
		pe.IMAGE_FILE_MACHINE_RISCV64,
		pe.IMAGE_FILE_MACHINE_RISCV128:
		return true
	}
	return false
}

func parseDataDirectories(reader io.ReaderAt, offset *int64, numDirs uint32, size int64, baseSize int64) ([]pe.DataDirectory, error) {
	if numDirs > 16 {
		return nil, fmt.Errorf("NumberOfRvaAndSizes exceeds maximum: %d > %d", numDirs, 16)
	}
	if size < baseSize+int64(numDirs)*8 {
		return nil, fmt.Errorf("optional header too small for NumberOfRvaAndSizes: %#x < %#x", size, baseSize+int64(numDirs)*8)
	}
	dirs := make([]pe.DataDirectory, numDirs)
	for i := range dirs {
		dir, err := readHeader[pe.DataDirectory](reader, offset)
		if err != nil {
			return nil, err
		}
		dirs[i] = *dir
	}
	*offset += size - baseSize - int64(numDirs)*8
	return dirs, nil
}
