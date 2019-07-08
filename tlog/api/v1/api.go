package v1

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	dcrtime "github.com/decred/dcrtime/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/util"
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

// RecordEntryNew returns an encoded RecordEntry structure.
// XXX this function does not belong here.
func RecordEntryNew(myId *identity.FullIdentity, dataHint, data []byte) RecordEntry {
	// Calculate hash
	h := sha256.New()
	h.Write(data)

	// Create record
	re := RecordEntry{
		Hash:     hex.EncodeToString(h.Sum(nil)),
		DataHint: base64.StdEncoding.EncodeToString(dataHint),
		Data:     base64.StdEncoding.EncodeToString(data),
	}

	// XXX don't sign when we don't have an identity. This is not
	// acceptable and only a temporary workaround until trillian properlly
	// supports ed25519.
	if myId != nil {
		re.PublicKey = hex.EncodeToString(myId.Public.Key[:])

		// Sign
		signature := myId.SignMessage([]byte(re.Hash))
		re.Signature = hex.EncodeToString(signature[:])
	}

	return re
}

// RecordEntryVerify ensures that a RecordEntry is valid.
// XXX this function does not belong here.
func RecordEntryVerify(record RecordEntry) error {
	// Decode identity
	id, err := util.IdentityFromString(record.PublicKey)
	if err != nil {
		return err
	}

	// Decode hash
	hash, err := hex.DecodeString(record.Hash)
	if err != nil {
		return err
	}

	// Decode signature
	s, err := hex.DecodeString(record.Signature)
	if err != nil {
		return err
	}
	var signature [64]byte
	copy(signature[:], s)

	// Decode data
	data, err := base64.StdEncoding.DecodeString(record.Data)
	if err != nil {
		return err
	}
	// Verify hash
	h := sha256.New()
	h.Write([]byte(data))
	if !bytes.Equal(hash, h.Sum(nil)) {
		return fmt.Errorf("invalid hash")
	}

	// Verify signature
	if !id.VerifyMessage([]byte(record.Hash), signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
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

type ListReply struct {
	Trees []*trillian.Tree `json:"trees"`
}

// RecordNew creates a new record that consists of several record entries. The
// server will not interpret the data at all. It will simply verify that the
// Data is signed with PublicKey.
type RecordNew struct {
	RecordEntries []RecordEntry `json:"recordentries"` // Entries to be stored
}

// RecordNewReply returns all pertinent information about a record. It returns
// trillian types so that the client can perform verifications.
type RecordNewReply struct {
	// XXX return inclusion proof?
	Leaves      []*trillian.QueuedLogLeaf `json:"leaves"`      // All leaves and their status
	Tree        trillian.Tree             `json:"tree"`        // TreeId is the record id
	InitialRoot trillian.SignedLogRoot    `json:"initialroot"` // Tree creation root
	STH         trillian.SignedLogRoot    `json:"sth"`         // Signed tree head after record addition
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
	// XXX return inclusion proof?
	Leaves []*trillian.QueuedLogLeaf `json:"leaves"` // All leaves and their status
	STH    trillian.SignedLogRoot    `json:"sth"`    // Signed tree head after record addition
}

// RecordGet retrieves the entire record including proofs. This is an expensive
// call.
type RecordGet struct {
	Id int64 `json:"id"` // Record ID
}

// RecordGetReply returns all record entries and the proofs.
// XXX Note that there corrently is a bunch of duplicate information flowing.
type RecordGetReply struct {
	Leaves        []*trillian.LogLeaf                  `json:"leaves"`                     // All leaves
	RecordEntries []RecordEntry                        `json:"recordentries"`              // All entries. This may be big
	Proofs        []trillian.GetInclusionProofResponse `json:"proofs"`                     // All proofs  + corresponding signed tree head
	STH           trillian.SignedLogRoot               `json:"sth"`                        // Signed tree head
	Anchor        dcrtime.ChainInformation             `json:"chaininformation,omitempty"` // Anchor information
	// XXX do we need to return the STH height this anchor anchored?
}

// RecordEntryIdentifier uniquely identifies a single leaf+data+proof.
type RecordEntryIdentifier struct {
	Id         int64  `json:"id"`         // Record ID
	MerkleHash string `json:"merklehash"` // Merkle hash
}

// RecordEntryProof contains an entire record entry + proof. If error is set
// the record could not be retrieved.
type RecordEntryProof struct {
	RecordEntry *RecordEntry                        `json:"recordentry,omitempty"`      // Data
	Leaf        *trillian.LogLeaf                   `json:"leaf,omitempty"`             // Requested Leaf
	Proof       *trillian.GetInclusionProofResponse `json:"proof,omitempty"`            // Proofs + corresponding signed tree head
	Anchor      dcrtime.ChainInformation            `json:"chaininformation,omitempty"` // Anchor information
	// XXX do we need to return the STH height this anchor anchored?
	Error string `json:"error,omitempty"` // Error is set when record could not be retrieved
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

// RecordFsckReply
// XXX Should we return all info to run fsck client side?
type RecordFsckReply struct {
	//Leaves        []*trillian.LogLeaf                  `json:"leaves"`                     // All leaves
	//RecordEntries []RecordEntry                        `json:"recordentries"`              // All entries. This may be big
	//Proofs        []trillian.GetInclusionProofResponse `json:"proofs"`                     // All proofs  + corresponding signed tree head
	//STH           trillian.SignedLogRoot               `json:"sth"`                        // Signed tree head
	//Anchor        dcrtime.ChainInformation             `json:"chaininformation,omitempty"` // Anchor information
	//// XXX do we need to return the STH height this anchor anchored?
}
