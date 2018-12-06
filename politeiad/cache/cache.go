package cache

import "errors"

var (
	// ErrShutdown is emitted when the cache is shutting down.
	ErrShutdown = errors.New("cache is shutting down")

	// ErrRecordNotFound is emitted when a record could not be found.
	ErrRecordNotFound = errors.New("record not found")
)

type File struct {
	Name    string // Basename of the file
	MIME    string // MIME type
	Digest  string // SHA256 of decoded Payload
	Payload string // base64 encoded file
}

type MetadataStream struct {
	ID      uint64 // Stream identity
	Payload string // String encoded metadata
}

type CensorshipRecord struct {
	Token     string // Censorship token
	Merkle    string // Merkle root of record
	Signature string // Signature of merkle+token
}

type Record struct {
	Version          string           // Version of this record
	Status           int              // Current status
	Timestamp        int64            // Last update
	CensorshipRecord CensorshipRecord // Censorship record
	Metadata         []MetadataStream // Metadata streams
	Files            []File           // Files that make up the record
}

type Cache interface {
	// Create a new record
	RecordNew(Record) error

	// Fetch an existing record
	RecordGet(string, string) (*Record, error)

	// Fetch the latest version of a record
	RecordGetLatest(string) (*Record, error)

	// Update an exisiting record
	RecordUpdate(Record) error

	// Update the status of a record
	RecordUpdateStatus(string, string, int, int64, []MetadataStream) error

	// Create cache tables if they do not already exist
	CreateTables() error

	// Close performs cleanup of the cache
	Close()
}
