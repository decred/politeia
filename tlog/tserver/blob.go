package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	v1 "github.com/decred/politeia/tlog/api/v1"
	"github.com/google/uuid"
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

// Unencrypted filesystem
var (
	ErrDoesntExist = errors.New("doesn't exist")

	_ Blob = (*blobFilesystem)(nil)
)

// blobFilesystem provides a blob filesystem that is encrypted if a private key
// is provided.
type blobFilesystem struct {
	path       string    // Location of files
	privateKey *[32]byte // Private key
}

func (b *blobFilesystem) Put(blob []byte) ([]byte, error) {
	var err error
	if b.privateKey != nil {
		blob, err = encryptAndPack(blob, b.privateKey)
		if err != nil {
			return nil, err
		}
	}
	filename := uuid.New().String()
	err = ioutil.WriteFile(filepath.Join(b.path, filename), blob, 0600)
	if err != nil {
		return nil, err
	}
	return []byte(filename), nil
}

func (b *blobFilesystem) Get(id []byte) ([]byte, error) {
	blob, err := ioutil.ReadFile(filepath.Join(b.path, string(id)))
	if err != nil {
		return nil, err
	}

	if b.privateKey != nil {
		return unpackAndDecrypt(b.privateKey, blob)
	}
	return blob, nil
}

func (b *blobFilesystem) Del(id []byte) error {
	err := os.Remove(filepath.Join(b.path, string(id)))
	if err != nil {
		// Always return doesn't exist
		return (ErrDoesntExist)
	}
	return nil
}

func (b *blobFilesystem) Enum(f func([]byte, []byte) error) error {
	files, err := ioutil.ReadDir(b.path)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.Name() == ".." {
			continue
		}
		// XXX should we return filesystem errors or wrap them?
		blob, err := b.Get([]byte(file.Name()))
		if err != nil {
			return err
		}
		err = f([]byte(file.Name()), blob)
		if err != nil {
			return err
		}
	}

	return nil
}

func BlobFilesystemNew(privateKey *[32]byte, path string) (Blob, error) {
	return &blobFilesystem{
		path:       path,
		privateKey: privateKey,
	}, nil
}
