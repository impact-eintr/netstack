package rand

import "crypto/rand"

// Reader is the default reader.
var Reader = rand.Reader

// Read implements io.Reader.Read.
func Read(b []byte) (int, error) {
	return rand.Read(b)
}
