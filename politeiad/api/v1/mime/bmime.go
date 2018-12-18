package mime

import (
	"errors"
	"net/http"

	svg "github.com/h2non/go-is-svg"
)

var (
	// validMimeTypesMap is a list of all acceptable MIME types that
	// can be communicated between client and server, structured
	// as a map for fast access.
	validMimeTypesMap = make(map[string]struct{})

	// DefaultMimeTypes is a list to be used as a default if this
	// config is not set manually.
	DefaultMimeTypes = []string{
		"image/png",
		"text/plain",
		"text/plain; charset=utf-8",
	}

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
