package util

import (
	"crypto/rand"
	"io"
)

// Random returns a variable number of bytes of random data.
func Random(n int) ([]byte, error) {
	k := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, k[:])
	if err != nil {
		return nil, err
	}

	return k, nil
}
