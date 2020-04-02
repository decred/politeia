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
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/thi4go/politeia/politeiad/api/v1/mime"
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

	// Digest
	h := sha256.New()
	h.Write(b)
	digest = hex.EncodeToString(h.Sum(nil))

	// Payload
	payload = base64.StdEncoding.EncodeToString(b)

	return
}

// LoadFile2 returns a file and its mime type.
func LoadFile2(filename string) (string, []byte, error) {
	var b []byte // file payload
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", nil, err
	}

	return mime.DetectMimeType(b), b, nil
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
func CleanAndExpandPath(path string) string {
	// Nothing to do when no path is given.
	if path == "" {
		return path
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows cmd.exe-style
	// %VARIABLE%, but the variables can still be expanded via POSIX-style
	// $VARIABLE.
	path = os.ExpandEnv(path)

	if !strings.HasPrefix(path, "~") {
		return filepath.Clean(path)
	}

	// Expand initial ~ to the current user's home directory, or ~otheruser
	// to otheruser's home directory.  On Windows, both forward and backward
	// slashes can be used.
	path = path[1:]

	var pathSeparators string
	if runtime.GOOS == "windows" {
		pathSeparators = string(os.PathSeparator) + "/"
	} else {
		pathSeparators = string(os.PathSeparator)
	}

	userName := ""
	if i := strings.IndexAny(path, pathSeparators); i != -1 {
		userName = path[:i]
		path = path[i:]
	}

	homeDir := ""
	var u *user.User
	var err error
	if userName == "" {
		u, err = user.Current()
	} else {
		u, err = user.Lookup(userName)
	}
	if err == nil {
		homeDir = u.HomeDir
	}
	// Fallback to CWD if user lookup fails or user has no home directory.
	if homeDir == "" {
		homeDir = "."
	}

	return filepath.Join(homeDir, path)
}
