package tlobe

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"io"

	"github.com/decred/politeia/tlog/api/v1"
	"golang.org/x/crypto/nacl/secretbox"
)

func blobify(re v1.RecordEntry) ([]byte, error) {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	enc := gob.NewEncoder(zw)
	err := enc.Encode(re)
	if err != nil {
		return nil, err
	}
	err = zw.Close() // we must flush gzip buffers
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func deblob(blob []byte) (*v1.RecordEntry, error) {
	zr, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	r := gob.NewDecoder(zr)
	var re v1.RecordEntry
	err = r.Decode(&re)
	if err != nil {
		return nil, err
	}
	return &re, nil
}

func NewKey() (*[32]byte, error) {
	var k [32]byte

	_, err := io.ReadFull(rand.Reader, k[:])
	if err != nil {
		return nil, err
	}

	return &k, nil
}

func encryptAndPack(data []byte, key *[32]byte) ([]byte, error) {
	var nonce [24]byte

	// random nonce
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	// encrypt data
	blob := secretbox.Seal(nil, data, &nonce, key)

	// pack all the things
	packed := make([]byte, len(nonce)+len(blob))
	copy(packed[0:], nonce[:])
	copy(packed[24:], blob)

	return packed, nil
}

func unpackAndDecrypt(key *[32]byte, packed []byte) ([]byte, error) {
	if len(packed) < 24 {
		return nil, errors.New("not an sbox file")
	}

	var nonce [24]byte
	copy(nonce[:], packed[0:24])

	decrypted, ok := secretbox.Open(nil, packed[24:], &nonce, key)
	if !ok {
		return nil, fmt.Errorf("could not decrypt")
	}
	return decrypted, nil
}

type Blob interface {
	Put([]byte) ([]byte, error)            // Store blob and return identifier
	Get([]byte) ([]byte, error)            // Get blob by identifier
	Del([]byte) error                      // Attempt to delete object
	Enum(func([]byte, []byte) error) error // Enumerate over all objects
}
