package pego

import "bytes"

// cstring converts ASCII byte sequence b to string.
// It stops once it finds 0 or reaches end of b.
func cstring(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		i = len(b)
	}
	return string(b[:i])
}
