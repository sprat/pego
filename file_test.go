package pego

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileRead(t *testing.T) {
	f, err := os.Open(filepath.Join("testfiles", "piano.exe"))
	if err != nil {
		t.Fatal("Cannot open test file")
	}
	defer f.Close()

	pe, err := NewPE(f)
	if err != nil {
		t.Fatal(err)
	}

	dosHeaderData := pe.DosHeader.Data

	got := dosHeaderData.Lfanew
	want := uint32(0xc0)
	if got != want {
		t.Errorf("dosHeaderData.Lfanew: got %x, wanted %x", got, want)
	}
}
