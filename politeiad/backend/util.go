package backend

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"strconv"

	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/util"
	"github.com/subosito/gozaru"
)

// VerifyContent verifies that all provided MetadataStream and File are sane.
func VerifyContent(metadata []MetadataStream, files []File, filesDel []string) error {
	// Make sure all metadata is within maxima.
	for _, v := range metadata {
		if v.ID > pd.MetadataStreamsMax-1 {
			return ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidMDID,
				ErrorContext: []string{
					strconv.FormatUint(v.ID, 10),
				},
			}
		}
	}
	for i := range metadata {
		for j := range metadata {
			// Skip self and non duplicates.
			if i == j || metadata[i].ID != metadata[j].ID {
				continue
			}
			return ContentVerificationError{
				ErrorCode: pd.ErrorStatusDuplicateMDID,
				ErrorContext: []string{
					strconv.FormatUint(metadata[i].ID, 10),
				},
			}
		}
	}

	// Prevent paths
	for i := range files {
		if filepath.Base(files[i].Name) != files[i].Name {
			return ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}
	}
	for _, v := range filesDel {
		if filepath.Base(v) != v {
			return ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					v,
				},
			}
		}
	}

	// Now check files
	if len(files) == 0 {
		return ContentVerificationError{
			ErrorCode: pd.ErrorStatusEmpty,
		}
	}

	// Prevent bad filenames and duplicate filenames
	for i := range files {
		for j := range files {
			if i == j {
				continue
			}
			if files[i].Name == files[j].Name {
				return ContentVerificationError{
					ErrorCode: pd.ErrorStatusDuplicateFilename,
					ErrorContext: []string{
						files[i].Name,
					},
				}
			}
		}
		// Check against filesDel
		for _, v := range filesDel {
			if files[i].Name == v {
				return ContentVerificationError{
					ErrorCode: pd.ErrorStatusDuplicateFilename,
					ErrorContext: []string{
						files[i].Name,
					},
				}
			}
		}
	}

	for i := range files {
		if gozaru.Sanitize(files[i].Name) != files[i].Name {
			return ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Validate digest
		d, ok := util.ConvertDigest(files[i].Digest)
		if !ok {
			return ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Decode base64 payload
		var err error
		payload, err := base64.StdEncoding.DecodeString(files[i].Payload)
		if err != nil {
			return ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidBase64,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Calculate payload digest
		dp := util.Digest(payload)
		if !bytes.Equal(d[:], dp) {
			return ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Verify MIME
		detectedMIMEType := mime.DetectMimeType(payload)
		if detectedMIMEType != files[i].MIME {
			return ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidMIMEType,
				ErrorContext: []string{
					files[i].Name,
					detectedMIMEType,
				},
			}
		}

		if !mime.MimeValid(files[i].MIME) {
			return ContentVerificationError{
				ErrorCode: pd.ErrorStatusUnsupportedMIMEType,
				ErrorContext: []string{
					files[i].Name,
					files[i].MIME,
				},
			}
		}
	}

	return nil
}
