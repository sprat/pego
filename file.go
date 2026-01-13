package pego

import (
	"debug/pe"
	"fmt"
	"io"
)

// Represents a PE file structure
type PE struct {
	DOSHeader   *Header[DOSHeader]
	DOSStub     *Segment
	PESignature *Header[PESignature]
	COFFHeader  *Header[pe.FileHeader]
}

// NewPE creates a PE instance
func NewPE(reader io.ReaderAt) (*PE, error) {
	var dosStub *Segment
	var peSignature *Header[PESignature]
	offset := int64(0)

	// DOS Header
	dosHeader, err := NewHeader[DOSHeader](reader, &offset)
	if err != nil {
		return nil, err
	}

	if dosHeader.Data.Magic == 0x5a4d {
		// DOS Stub
		peHeaderOffset := int64(dosHeader.Data.Lfanew)
		dosStubSize := peHeaderOffset - offset
		dosStub = NewSegment(reader, &offset, dosStubSize)

		// PE Signature
		peSignature, err = NewHeader[PESignature](reader, &offset)
		if err != nil {
			return nil, err
		}
		if peSignature.Data != 0x00004550 {
			return nil, fmt.Errorf("invalid PE file signature: %#x", peSignature.Data)
		}
	} else {
		offset = 0
		dosHeader = nil
	}

	// COFF Header
	coffHeader, err := NewHeader[pe.FileHeader](reader, &offset)
	if err != nil {
		return nil, err
	}

	// make sure the machine type is valid
	if !isValidMachine(coffHeader.Data.Machine) {
		return nil, fmt.Errorf("unrecognized PE machine: %#x", coffHeader.Data.Machine)
	}

	// TODO: add protections to defend against malicious files (e.g. oversized segments...)

	return &PE{
		DOSHeader:   dosHeader,
		DOSStub:     dosStub,
		PESignature: peSignature,
		COFFHeader:  coffHeader,
	}, nil
}

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
