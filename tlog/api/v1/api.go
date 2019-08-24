package v1

import (
	"fmt"

	dcrtime "github.com/decred/dcrtime/api/v1"
	"github.com/google/trillian"
)

type ErrorStatusT int

const (
	// Routes
	RouteList             = "/v1/list/"             // list all records
	RoutePublicKey        = "/v1/publickey/"        // public signing key
	RouteRecordNew        = "/v1/recordnew/"        // new record
	RouteRecordGet        = "/v1/recordget/"        // retrieve record and proofs
	RouteRecordEntriesGet = "/v1/recordentriesget/" // retrieve record entries and proofs
	RouteRecordAppend     = "/v1/append/"           // append data to record
	RouteRecordFsck       = "/v1/fsck/"             // fsck record

	// Error status codes
	ErrorStatusInvalid      ErrorStatusT = 0
	ErrorStatusInvalidInput ErrorStatusT = 1

	Forward = "X-Forwarded-For"
)

var (
	// ErrorStatus converts error status codes to human readable text.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:      "invalid status",
		ErrorStatusInvalidInput: "invalid input",
	}
)

// UserError represents an error that is caused by something that the user
// did (malformed input, bad timing, etc).
type UserError struct {
	ErrorCode    ErrorStatusT
	ErrorContext []string
}

// Error satisfies the error interface.
func (e UserError) Error() string {
	return fmt.Sprintf("user error code: %v", e.ErrorCode)
}

// ErrorReply are replies that the server returns a when it encounters an
// unrecoverable problem while executing a command.  The HTTP Error Code
// shall be 500 if it's an internal server error or 4xx if it's a user error.
type ErrorReply struct {
	ErrorCode    int64    `json:"errorcode,omitempty"`
	ErrorContext []string `json:"errorcontext,omitempty"`
}

const (
	// DataDescriptor.Type values. These may be freely edited since they
	// are solely hints to the application.
	DataTypeKeyValue  = "kv"     // Descriptor is empty but data is key/value
	DataTypeMime      = "mime"   // Descriptor contains a mime type
	DataTypeStructure = "struct" // Descriptor contains a structure

	DataDescriptorAnchor = "anchor" // Data is JSON Anchor structure
)

// DataDescriptor provides hints about a data blob. In practise we JSON encode
// this struture and stuff it into RecordEntry.DataHint.
type DataDescriptor struct {
	Type       string `json:"type,omitempty"`       // Type of data that is stored
	Descriptor string `json:"descriptor,omitempty"` // Description of the data
	ExtraData  string `json:"extradata,omitempty"`  // Value to be freely used by caller
}

// DataKeyValue is an encoded key/value pair.
type DataKeyValue struct {
	Key   string `json:"key"`   // Key
	Value string `json:"value"` // Value
}

// DataAnchor describes what is stored in dcrtime. We store the SHA256 hash of
// STH.LogRoot in dcrtime
type DataAnchor struct {
	RecordId     int64                  `json:"recordid"`     // Record ID this STH belongs to
	STH          trillian.SignedLogRoot `json:"sth"`          // Signed tree head
	VerifyDigest dcrtime.VerifyDigest   `json:"verifydigest"` // dcrtime digest structure
}

// Record contains user provided data and user attestation.
type RecordEntry struct {
	PublicKey string `json:"publickey"` // Hex encoded public key used sign Data
	Hash      string `json:"hash"`      // Hex encoded hash of the string data
	Signature string `json:"signature"` // Hex encoded client ed25519 signature of Hash
	DataHint  string `json:"datahint"`  // Hint that describes the data, base64 encoded
	Data      string `json:"data"`      // Data payload, base64 encoded
}

// PublicKey retrieves the server public signing key.
type PublicKey struct{}

// PublicKeyReply returns the server's signing key. It is a base64 encoded DER
// format.
type PublicKeyReply struct {
	SigningKey string `json:"signingkey"` // base64 encoded DER key
}

// List request a list of all trees.
type List struct{}

// ListReply returns a list of all trees.
type ListReply struct {
	Trees []*trillian.Tree `json:"trees"`
}

// RecordNew creates a new record that consists of several record entries. The
// server will not interpret the data at all. It will simply verify that the
// Data is signed with PublicKey.
type RecordNew struct {
	RecordEntries []RecordEntry `json:"recordentries"` // Entries to be stored
}

// QueuedLeafProof contains a queued log leaf and an inclusion proof for the
// leaf. A queued log leaf will not have a leaf index so any client side
// verification must be done using the leaf hash.
type QueuedLeafProof struct {
	QueuedLeaf trillian.QueuedLogLeaf `json:"queuedleaf"`      // A queued leaf and its status
	Proof      *trillian.Proof        `json:"proof;omitempty"` // Leaf inclusion proof
}

// RecordNewReply returns all pertinent information about a record. It returns
// trillian types so that the client can perform verifications.
type RecordNewReply struct {
	Tree        trillian.Tree          `json:"tree"`        // TreeId is the record id
	InitialRoot trillian.SignedLogRoot `json:"initialroot"` // Tree creation root
	STH         trillian.SignedLogRoot `json:"sth"`         // Signed tree head after record addition
	Proofs      []QueuedLeafProof      `json:"proofs"`      // Queued leaves and their proofs
}

// RecordAppend adds new record entries to a record.  The server will not
// interpret the data at all. It will simply verify that the Data is signed
// with PublicKey. It also does not overwrite or delete items. The caller is
// expected to keep track of ordering etc. Note that The leafs do have
// timestamps.
type RecordAppend struct {
	Id            int64         `json:"id"`            // Record ID
	RecordEntries []RecordEntry `json:"recordentries"` // Entries to be stored
}

// RecordAppendReply returns all pertinent information about the record entries
// that were append to a record. It returns trillian types so that the client
// can perform verifications.
type RecordAppendReply struct {
	STH    trillian.SignedLogRoot `json:"sth"`    // Signed tree head after record addition
	Proofs []QueuedLeafProof      `json:"proofs"` // Queued leaves and their proofs
}

// RecordGet retrieves the entire record including proofs. This is an expensive
// call.
type RecordGet struct {
	Id int64 `json:"id"` // Record ID
}

// RecordGetReply returns all record entries and the proofs.
type RecordGetReply struct {
	Proofs []RecordEntryProof     `json:"recordentries"` // All entries and proofs. This may be big
	STH    trillian.SignedLogRoot `json:"sth"`           // Signed tree head
}

// RecordEntryIdentifier uniquely identifies a single leaf+data+proof.
type RecordEntryIdentifier struct {
	Id         int64  `json:"id"`         // Record ID
	MerkleHash string `json:"merklehash"` // Merkle hash
}

// RecordEntryProof contains an entire record entry and anchor proof. The STH,
// Proof, and Anchor will ony be present once the RecordEntry has been
// successfully anchored. The STH corresponds to the LogRoot that was anchored.
// It is not the STH of the current tree. If error is set the record could not
// be retrieved.
type RecordEntryProof struct {
	RecordEntry *RecordEntry              `json:"recordentry,omitempty"` // Data
	Leaf        *trillian.LogLeaf         `json:"leaf,omitempty"`        // Requested Leaf
	STH         *trillian.SignedLogRoot   `json:"sth,omitempty"`         // Signed tree head
	Proof       *trillian.Proof           `json:"proof,omitempty"`       // Inclusion proof for STH
	Anchor      *dcrtime.ChainInformation `json:"anchor,omitempty"`      // Anchor info for STH
	Error       string                    `json:"error,omitempty"`       // Error is set when record could not be retrieved
}

// RecordEntriesGet attempts to retrieve a batch of record entries and their
// proofs.
type RecordEntriesGet struct {
	Entries []RecordEntryIdentifier `json:"entries"` // Entries to retrieve
}

// RecordEntriesGetReply is the array of the requested record entries and proofs.
type RecordEntriesGetReply struct {
	Proofs []RecordEntryProof `json:"proofs"` // All proofs and data
}

// RecordFsck performs an fsck on the record to ensure integrity.
type RecordFsck struct {
	Id int64 `json:"id"` // Record ID
}

// RecordFsckReply is the reply to the RecordFsck command.
type RecordFsckReply struct{}
