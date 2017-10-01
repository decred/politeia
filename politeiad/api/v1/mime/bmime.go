package mime

import "errors"

var (
	// ValidMimeTypesMap describes all acceptable MIME types that can be
	// communicated between client and server.
	ValidMimeTypesMap = map[string]struct{}{
		"image/png":                 {},
		"text/plain":                {},
		"text/plain; charset=utf-8": {},
	}

	// ValidMimeTypesList is a list of all the keys within ValidMimeTypesMap.
	ValidMimeTypesList []string

	ErrUnsupportedMimeType = errors.New("unsupported MIME type")
)

func MimeValid(s string) bool {
	_, ok := ValidMimeTypesMap[s]
	return ok
}
