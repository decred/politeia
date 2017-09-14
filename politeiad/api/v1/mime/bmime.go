package mime

import "errors"

var (
	// validMimeType describes are all acceptable MIME types that can be
	// communicated between client and server.
	validMimeType = map[string]struct{}{
		"image/png":                 {},
		"text/plain":                {},
		"text/plain; charset=utf-8": {},
	}
	ErrUnsupportedMimeType = errors.New("unsuported MIME type")
)

func MimeValid(s string) bool {
	_, ok := validMimeType[s]
	return ok
}
