// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gitbe

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/decred/dcrtime/merkle"
	"github.com/syndtr/goleveldb/leveldb"
)

// The database contains 3 types of records:
//	[lastanchor][LastAnchor]
//	[Merkle Root][Anchor]
//	[unconfirmed][UnconfirmedAnchor]
//
// The LastAnchor record is used to persist the last committed anchor.  The
// information that is contained in the record allows us to create a git log
// range to calculate the new LastAnchor.  There is always one and only one
// LastAnchor record in the database (with the exception when bootstrapping the
// system).
//
// The anchor records simply contain all information that went into creating an
// anchor and are essentially redundant from a data perspective.  We keep this
// information for caching purposes so that we don't have to parse git output.
//
// The unconfirmed anchor records are a list of all anchor merkle roots that
// have not been confirmed by dcrtime.  This record is used at startup time to
// identify what anchors have not been confirmed by dcrtime and to resume
// waiting for their confirmation.  Once an anchor is confirmed it should be
// removed from this list; this operation SHALL be atomic.

const (
	DbVersion  uint32 = 1
	VersionKey        = "version"
)

type Version struct {
	Version uint32 // Database version
	Time    int64  // Time of record creation
}

// encodeVersion encodes Version into a JSON byte slice.
func encodeVersion(version Version) ([]byte, error) {
	b, err := json.Marshal(version)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeVersion decodes a JSON byte slice into a Version.
func DecodeVersion(payload []byte) (*Version, error) {
	var version Version

	err := json.Unmarshal(payload, &version)
	if err != nil {
		return nil, err
	}

	return &version, nil
}

// AnchorType discriminates between the various Anchor record types.
type AnchorType uint32

const (
	AnchorInvalid    AnchorType = 0 // Invalid anchor
	AnchorUnverified AnchorType = 1 // Unverified anchor
	AnchorVerified   AnchorType = 2 // Verified anchor
)

// Anchor is a database record where the merkle root of digests is the key.
// This record is pointed at by LastAnchor.Root.
//
// len(Digests) == len(Messages) and index offsets are linked. e.g. Digests[15]
// commit messages is in Messages[15].
type Anchor struct {
	Type     AnchorType // Type of anchor this record represents
	Digests  [][]byte   // All digests that were merkled to get to key of record
	Messages []string   // All one-line Commit messages
	Time     int64      // OS time when record was created

	// dcrtime portion, only valid when Type == AnchorVerified
	ChainTimestamp int64  // Time anchor was confirmed on blockchain
	Transaction    string // Anchor transaction
}

// newAnchorRecord creates an Anchor Record and the Merkle Root from the
// provided pieces.  Note that the merkle root is of the git digests!
func newAnchorRecord(t AnchorType, digests []*[sha256.Size]byte, messages []string) (*Anchor, *[sha256.Size]byte, error) {
	if len(digests) != len(messages) {
		return nil, nil, fmt.Errorf("invalid digest and messages length")
	}

	if t == AnchorInvalid {
		return nil, nil, fmt.Errorf("invalid anchor type")
	}

	a := Anchor{
		Type:     t,
		Messages: messages,
		Digests:  make([][]byte, 0, len(digests)),
		Time:     time.Now().Unix(),
	}

	for _, digest := range digests {
		d := make([]byte, sha256.Size)
		copy(d, digest[:])
		a.Digests = append(a.Digests, d)
	}

	return &a, merkle.Root(digests), nil
}

// encodeAnchor encodes Anchor into a JSON byte slice.
func encodeAnchor(anchor Anchor) ([]byte, error) {
	b, err := json.Marshal(anchor)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeAnchor decodes a JSON byte slice into an Anchor.
func DecodeAnchor(payload []byte) (*Anchor, error) {
	var anchor Anchor

	err := json.Unmarshal(payload, &anchor)
	if err != nil {
		return nil, err
	}

	return &anchor, nil
}

// writeAnchorRecord encodes and writes the supplied record to the
// database.
//
// This function must be called with the lock held.
func (g *gitBackEnd) writeAnchorRecord(key [sha256.Size]byte, anchor Anchor) error {
	// make key
	k := make([]byte, sha256.Size)
	copy(k, key[:])

	// Encode
	la, err := encodeAnchor(anchor)
	if err != nil {
		return err
	}

	// Use a batch for now
	batch := new(leveldb.Batch)
	batch.Put(k, la)

	return g.db.Write(batch, nil)
}

// readAnchorRecord retrieves the anchor record based on the provided merkle
// root.
//
// This function must be called with the lock held.
func (g *gitBackEnd) readAnchorRecord(key [sha256.Size]byte) (*Anchor, error) {
	// make key
	k := make([]byte, sha256.Size)
	copy(k, key[:])

	// Get anchor from db
	payload, err := g.db.Get(k, nil)
	if err != nil {
		return nil, err
	}

	// Decode
	return DecodeAnchor(payload)
}

const (
	LastAnchorKey = "lastanchor" // Key to identify LastAnchor
)

// LastAnchor record.
type LastAnchor struct {
	Last   []byte // Last git digest that was anchored
	Time   int64  // OS time when record was created
	Merkle []byte // Merkle root that points to Anchor record, if valid
}

// encodeLastAnchor encodes LastAnchor into a byte slice.
func encodeLastAnchor(lastAnchor LastAnchor) ([]byte, error) {
	b, err := json.Marshal(lastAnchor)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeLastAnchor decodes a payload into a LastAnchor.
func DecodeLastAnchor(payload []byte) (*LastAnchor, error) {
	var lastAnchor LastAnchor

	err := json.Unmarshal(payload, &lastAnchor)
	if err != nil {
		return nil, err
	}

	return &lastAnchor, nil
}

// writeLastAnchorRecord encodes and writes the supplied record to the
// database.
//
// This function must be called with the lock held.
func (g *gitBackEnd) writeLastAnchorRecord(lastAnchor LastAnchor) error {
	// Encode
	la, err := encodeLastAnchor(lastAnchor)
	if err != nil {
		return err
	}

	// Use a batch for now
	batch := new(leveldb.Batch)
	batch.Put([]byte(LastAnchorKey), la)

	return g.db.Write(batch, nil)
}

// readLastAnchorRecord retrieves the last anchor record.
//
// This function must be called with the lock held.
func (g *gitBackEnd) readLastAnchorRecord() (*LastAnchor, error) {
	// Get last anchor from db
	payload, err := g.db.Get([]byte(LastAnchorKey), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return &LastAnchor{}, nil
		}
		return nil, err
	}

	// Decode
	return DecodeLastAnchor(payload)
}

// openDB opens and/or creates the backend database.  The database is versioned
// and upgrade code should be added to this function when needed.
func (g *gitBackEnd) openDB(path string) error {
	var err error
	g.db, err = leveldb.OpenFile(path, nil)
	if err != nil {
		return err
	}

	// See if we need to write a version record
	exists, err := g.db.Has([]byte(VersionKey), nil)
	if err != nil || exists {
		return err
	}

	// Write version record
	v, err := encodeVersion(Version{
		Version: DbVersion,
		Time:    time.Now().Unix(),
	})
	if err != nil {
		return err
	}
	return g.db.Put([]byte(VersionKey), v, nil)
}

const (
	UnconfirmedKey = "unconfirmed"
)

type UnconfirmedAnchor struct {
	Merkles [][]byte // List of Merkle root that points to Anchor records
}

// encodeUnconfirmedAnchor encodes an UnconfirmedAnchor record into a JSON byte
// slice.
func encodeUnconfirmedAnchor(unconfirmed UnconfirmedAnchor) ([]byte, error) {
	b, err := json.Marshal(unconfirmed)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeUnconfirmedAnchor decodes a JSON byte slice into an UnconfirmedAnchor
// record.
func DecodeUnconfirmedAnchor(payload []byte) (*UnconfirmedAnchor, error) {
	var unconfirmed UnconfirmedAnchor

	err := json.Unmarshal(payload, &unconfirmed)
	if err != nil {
		return nil, err
	}

	return &unconfirmed, nil
}

// writeUnconfirmedAnchorRecord encodes and writes the supplied record to the
// database.
//
// This function must be called with the lock held.
func (g *gitBackEnd) writeUnconfirmedAnchorRecord(unconfirmed UnconfirmedAnchor) error {
	// Encode
	ua, err := encodeUnconfirmedAnchor(unconfirmed)
	if err != nil {
		return err
	}

	// Use a batch for now
	batch := new(leveldb.Batch)
	batch.Put([]byte(UnconfirmedKey), ua)

	return g.db.Write(batch, nil)
}

// readUnconfirmedAnchorRecord retrieves the unconfirmed anchor record.
//
// This function must be called with the lock held.
func (g *gitBackEnd) readUnconfirmedAnchorRecord() (*UnconfirmedAnchor, error) {
	// Get anchor from db
	payload, err := g.db.Get([]byte(UnconfirmedKey), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return &UnconfirmedAnchor{}, nil
		}
		return nil, err
	}

	// Decode
	return DecodeUnconfirmedAnchor(payload)
}
