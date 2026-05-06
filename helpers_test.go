package pego

import (
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func openTestFile(t *testing.T, name string) *os.File {
	t.Helper()
	file, err := os.Open(filepath.Join("testfiles", name))
	assert.NilError(t, err)
	t.Cleanup(func() { file.Close() })
	return file
}
