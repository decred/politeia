package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	svg "github.com/h2non/go-is-svg"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
)

var (
	// validMimeTypesMap is a list of all acceptable MIME types that
	// can be communicated between client and server, structured
	// as a map for fast access.
	validMimeTypesMap = make(map[string]struct{})

	ErrUnsupportedMimeType = errors.New("unsupported MIME type")
)

// MimeValid returns true if the passed string is a valid
// MIME type, false otherwise.
func MimeValid(s string) bool {
	_, ok := validMimeTypesMap[s]
	return ok
}

// DetectMimeType returns the file MIME type
func DetectMimeType(data []byte) string {
	// svg needs a specific check because the algorithm
	// implemented by http.DetectContentType doesn't detect svg
	if svg.IsSVG(data) {
		return "image/svg+xml"
	}
	return http.DetectContentType(data)
}

// SetMimeTypesMap sets valid mimetypes list with loaded config
func SetMimeTypesMap(validMimeTypesCfg []string) {
	for _, m := range validMimeTypesCfg {
		validMimeTypesMap[m] = struct{}{}
	}
}

// Verify ensures that a CensorshipRecord properly describes the array of
// files.
func VerifyCensorshipRecordFiles(pid identity.PublicIdentity, csr v1.CensorshipRecord, files []v1.File) error {
	digests := make([]*[sha256.Size]byte, 0, len(files))
	for _, file := range files {
		payload, err := base64.StdEncoding.DecodeString(file.Payload)
		if err != nil {
			return v1.ErrInvalidBase64
		}

		// MIME
		mimeType := DetectMimeType(payload)
		if !MimeValid(mimeType) {
			return ErrUnsupportedMimeType
		}

		// Digest
		h := sha256.New()
		h.Write(payload)
		d := h.Sum(nil)
		var digest [sha256.Size]byte
		copy(digest[:], d)

		digests = append(digests, &digest)
	}

	// Verify merkle root
	root := merkle.Root(digests)
	if hex.EncodeToString(root[:]) != csr.Merkle {
		return v1.ErrInvalidMerkle
	}

	s, err := hex.DecodeString(csr.Signature)
	if err != nil {
		return v1.ErrInvalidHex
	}
	var signature [identity.SignatureSize]byte
	copy(signature[:], s)
	r := hex.EncodeToString(root[:])
	if !pid.VerifyMessage([]byte(r+csr.Token), signature) {
		return v1.ErrCorrupt
	}

	return nil
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
	mimeType = DetectMimeType(b)
	if !MimeValid(mimeType) {
		err = ErrUnsupportedMimeType
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
