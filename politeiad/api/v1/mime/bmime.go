package mime

import "errors"

var (
	// validMimeTypesList is a list of all acceptable MIME types that
	// can be communicated between client and server.
	validMimeTypesList = []string{
		"image/png",
		"image/svg+xml",
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

func init() {
	for _, v := range validMimeTypesList {
		validMimeTypesMap[v] = struct{}{}
	}
}
