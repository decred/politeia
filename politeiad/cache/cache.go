package cache

import "errors"

type RecordStatusT int

var (
	// ErrShutdown is emitted when the cache is shutting down.
	ErrShutdown = errors.New("cache is shutting down")

	// ErrRecordNotFound is emitted when a record could not be found.
	ErrRecordNotFound = errors.New("record not found")
)

const (
	// Record status codes
	RecordStatusInvalid           RecordStatusT = 0 // Invalid status
	RecordStatusNotFound          RecordStatusT = 1 // Record not found
	RecordStatusNotReviewed       RecordStatusT = 2 // Record has not been reviewed
	RecordStatusCensored          RecordStatusT = 3 // Record has been censored
	RecordStatusPublic            RecordStatusT = 4 // Record is publicly visible
	RecordStatusUnreviewedChanges RecordStatusT = 5 // Unvetted record that has been changed
	RecordStatusArchived          RecordStatusT = 6 // Vetted record that has been archived
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
	Status           RecordStatusT    // Current status
	Timestamp        int64            // Last update
	CensorshipRecord CensorshipRecord // Censorship record
	Metadata         []MetadataStream // Metadata streams
	Files            []File           // Files that make up the record
}

type Cache interface {
	// Create a new record
	RecordNew(Record) error

	// Lookup an existing record
	RecordGet(string, string) (*Record, error)

	// Lookup the latest version of a record
	RecordGetLatest(string) (*Record, error)

	// Update an exisiting record
	RecordUpdate(Record) error

	// Update the status of a record
	RecordUpdateStatus(string, string, RecordStatusT, int64,
		[]MetadataStream) error

	// Plugin pass-through command
	Plugin(string, string, string) (string, string, error)

	// Lookup the data that was created by a plugin command
	// PluginGet

	// Create the cache tables if they do not already exist
	CreateTables() error

	// Close performs cleanup of the cache
	Close()
}
