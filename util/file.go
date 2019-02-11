// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

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
	return mime.DetectMimeType(b[:n]), nil
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
	mimeType = mime.DetectMimeType(b)
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

// FilesExists reports whether the named file or directory exists.
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// CleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func CleanAndExpandPath(path, homeDir string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but they variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}
