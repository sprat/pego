package pego

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

// PE represents a Portable Executable file structure.
type PE struct {
	DOSHeader        *Header[DOSHeader]
	DOSStub          *Segment
	PESignature      *Header[PESignature]
	COFFHeader       *Header[COFFHeader]
	OptionalHeader32 *Header[OptionalHeader32]
	OptionalHeader64 *Header[OptionalHeader64]
}

// NewPE parses a Portable Executable or plain COFF file from reader.
// It supports both PE files (with a DOS header) and plain COFF object files.
// Returns an error if the input is malformed or truncated.
func NewPE(reader io.ReaderAt) (*PE, error) {
	p := PE{}
	offset := int64(0)

	// DOS Header.
	dosHeader, err := NewHeader[DOSHeader](reader, &offset)
	if err == nil && dosHeader.Data.Magic == DOSHeaderMagic {
		p.DOSHeader = dosHeader

		// DOS Stub.
		peHeaderOffset := int64(dosHeader.Data.Lfanew)
		dosStubSize := peHeaderOffset - offset
		p.DOSStub = NewSegment(reader, &offset, dosStubSize)

		// PE Signature.
		p.PESignature, err = NewHeader[PESignature](reader, &offset)
		if err != nil {
			return nil, err
		}
		if p.PESignature.Data != PESignatureMagic {
			return nil, fmt.Errorf("invalid PE file signature: %#x", p.PESignature.Data)
		}
	} else {
		// Not a PE file with a DOS header, treat as a plain COFF file.
		// It will fail later if the COFF header is not valid.
		offset = 0
	}

	// COFF Header.
	p.COFFHeader, err = NewHeader[COFFHeader](reader, &offset)
	if err != nil {
		return nil, err
	}

	// Make sure the machine type is valid.
	if !isValidMachine(p.COFFHeader.Data.Machine) {
		return nil, fmt.Errorf("unrecognized PE machine: %#x", p.COFFHeader.Data.Machine)
	}

	// Optional Header.
	optionalHeaderSize := p.COFFHeader.Data.SizeOfOptionalHeader
	if optionalHeaderSize > 0 {
		var magicBytes [2]byte

		// Read the magic number to determine if it's PE32 or PE32+.
		_, err = reader.ReadAt(magicBytes[:], offset)
		if err != nil {
			return nil, io.ErrUnexpectedEOF
		}

		magic := binary.LittleEndian.Uint16(magicBytes[:])
		switch magic {
		case PE32Magic:
			p.OptionalHeader32, err = NewHeader[OptionalHeader32](reader, &offset)
		case PE32PlusMagic:
			p.OptionalHeader64, err = NewHeader[OptionalHeader64](reader, &offset)
		default:
			err = fmt.Errorf("invalid optional header magic: %#x", magic)
		}

		if err != nil {
			return nil, err
		}

		var expectedSize uint16
		if p.OptionalHeader32 != nil {
			expectedSize = uint16(p.OptionalHeader32.Size())
		} else {
			expectedSize = uint16(p.OptionalHeader64.Size())
		}

		if optionalHeaderSize != expectedSize {
			return nil, fmt.Errorf("optional header size does not match the expected size: %#x != %#x", optionalHeaderSize, expectedSize)
		}
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
