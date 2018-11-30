package mime

import (
	"errors"
	"net/http"

	svg "github.com/h2non/go-is-svg"
)

var (
	// validMimeTypesList is a list of all acceptable MIME types that
	// can be communicated between client and server.
	validMimeTypesList = []string{
		"image/png",
		"text/plain",
		"text/plain; charset=utf-8",
	}

	// validMimeTypesMap is the same as ValidMimeTypesList, but structured
	// as a map for fast access.
	validMimeTypesMap = make(map[string]struct{}, len(validMimeTypesList))

	ErrUnsupportedMimeType = errors.New("unsupported MIME type")
)

// MimeValid returns true if the passed string is a valid
// MIME type, false otherwise.
func MimeValid(s string) bool {
	_, ok := validMimeTypesMap[s]
	return ok
}

// ValidMimeTypes returns the list of supported MIME types.
func ValidMimeTypes() []string {
	return validMimeTypesList
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

func init() {
	for _, v := range validMimeTypesList {
		validMimeTypesMap[v] = struct{}{}
	}
}
