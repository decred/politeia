package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/decred/politeia/politeiad/api/v1/mime"
)

// MimeFile returns the MIME type of a file.
func MimeFile(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// We need up to 512 bytes
	b := make([]byte, 512)
	n, err := f.Read(b)
	if err != nil {
		return "", err
	}

	// Clip buffer to prevent detecting binary files.
	return http.DetectContentType(b[:n]), nil
}

// DigestFile returns the SHA256 of a file.
func DigestFile(filename string) (string, error) {
	b, err := DigestFileBytes(filename)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DigestFileBytes returns the SHA256 of a file.
func DigestFileBytes(filename string) ([]byte, error) {
	h := sha256.New()
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err = io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Base64File returns the base64 content of a file.
func Base64File(filename string) (string, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

// LoadFile loads a file of disk and returns the MIME type, the sha256 digest
// and the payload encoded as base64.  If any of the intermediary operations
// fail the function will return an error instead.
func LoadFile(filename string) (mimeType string, digest string, payload string, err error) {
	var b []byte // file payload
	b, err = ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	// MIME
	mimeType = http.DetectContentType(b)
	if !mime.MimeValid(mimeType) {
		err = mime.ErrUnsupportedMimeType
		return
	}

	// Digest
	h := sha256.New()
	h.Write(b)
	digest = hex.EncodeToString(h.Sum(nil))

	// Payload
	payload = base64.StdEncoding.EncodeToString(b)

	return
}
