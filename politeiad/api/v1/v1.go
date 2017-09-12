// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
)

type StatusT int

const (
	// Routes
	IdentityRoute    = "/v1/identity/"    // Retrieve identity
	NewRoute         = "/v1/new/"         // New proposal
	GetUnvettedRoute = "/v1/getunvetted/" // Retrieve unvetted proposal
	GetVettedRoute   = "/v1/getvetted/"   // Retrieve vetted proposal

	// Auth required
	InventoryRoute         = "/v1/inventory/"         // Inventory proposals
	SetUnvettedStatusRoute = "/v1/setunvettedstatus/" // Set unvetted status

	ChallengeSize = 32 // Size of challenge token in bytes

	// Status codes (set and get)
	StatusInvalid     StatusT = 0 // Invalid status
	StatusNotFound    StatusT = 1 // Proposal not found
	StatusNotReviewed StatusT = 2 // Proposal has not been reviewed
	StatusCensored    StatusT = 3 // Proposal has been censored
	StatusPublic      StatusT = 4 // Proposal is publicly visible

	// Default network bits
	DefaultMainnetHost = "politeia.decred.org"
	DefaultMainnetPort = "49374"
	DefaultTestnetHost = "politeia-testnet.decred.org"
	DefaultTestnetPort = "59374"
)

var (
	// Status converts status codes to human readable text.
	Status = map[StatusT]string{
		StatusInvalid:     "invalid status",
		StatusNotFound:    "not found",
		StatusNotReviewed: "not reviewed",
		StatusCensored:    "censored",
		StatusPublic:      "public",
	}

	// Input validation
	RegexpSHA256 = regexp.MustCompile("[A-Fa-f0-9]{64}")

	// Verification errors
	ErrInvalidHex    = errors.New("corrupt hex string")
	ErrInvalidBase64 = errors.New("corrupt base64")
	ErrInvalidMerkle = errors.New("merkle roots do not match")
	ErrCorrupt       = errors.New("signature verification failed")
)

// Verify ensures that a CensorshipRecord properly describes the array of
// files.
func Verify(pid identity.PublicIdentity, csr CensorshipRecord, files []File) error {
	digests := make([]*[sha256.Size]byte, 0, len(files))
	for _, file := range files {
		payload, err := base64.StdEncoding.DecodeString(file.Payload)
		if err != nil {
			return ErrInvalidBase64
		}

		// MIME
		mimeType := http.DetectContentType(payload)
		if !mime.MimeValid(mimeType) {
			return mime.ErrUnsupportedMimeType
		}

		// Digest
		h := sha256.New()
		h.Write(payload)
		d := h.Sum(nil)
		var digest [sha256.Size]byte
		copy(digest[:], d)

		digests = append(digests, &digest)
	}

	// Verify merkle root
	root := merkle.Root(digests)
	if hex.EncodeToString(root[:]) != csr.Merkle {
		return ErrInvalidMerkle
	}

	// Verify merkle+token signature
	token, err := hex.DecodeString(csr.Token)
	if err != nil {
		return ErrInvalidHex
	}

	merkleToken := make([]byte, len(root)+len(token))
	copy(merkleToken, root[:])
	copy(merkleToken[len(root[:]):], token)

	s, err := hex.DecodeString(csr.Signature)
	if err != nil {
		return ErrInvalidHex
	}
	var signature [identity.SignatureSize]byte
	copy(signature[:], s)
	if !pid.VerifyMessage(merkleToken, signature) {
		return ErrCorrupt
	}

	return nil
}

// CensorshipRecord contains the proof that a proposal was accepted for review.
// The proof is verifiable on the client side.
//
// The Merkle field contains the ordered merkle root of all files in the proposal.
// The Token field contains a random censorship token that is signed by the
// server private key.  The token can be used on the client to verify the
// authenticity of the CensorshipRecord.
type CensorshipRecord struct {
	Token     string `json:"token"`     // Censorship token
	Merkle    string `json:"merkle"`    // Merkle root of proposal
	Signature string `json:"signature"` // Signature of merkle+token
}

// Identity requests the proposal server identity.
type Identity struct {
	Challenge string `json:"challenge"` // Random challenge
}

// IdentityReply contains the server public identity.
type IdentityReply struct {
	Response string `json:"response"` // Signature of Challenge
	Name     string `json:"name"`     // FQDN
	Nick     string `json:"nick"`     // Server nick name
	Identity string `json:"identity"` // Public identity
	Key      string `json:"key"`      // Public key
}

// File describes an individual file that is part of the proposal.  The
// directory structure must be flattened.  The server side SHALL verify MIME
// and Digest.
type File struct {
	Name    string `json:"name"`    // Suggested filename
	MIME    string `json:"mime"`    // Mime type
	Digest  string `json:"digest"`  // Payload digest
	Payload string `json:"payload"` // File content
}

type ProposalRecord struct {
	Name      string  `json:"name"`      // Suggested short proposal name
	Status    StatusT `json:"status"`    // Current status of proposal
	Timestamp int64   `json:"timestamp"` // Last update of proposal
	Files     []File  `json:"files"`     // Files that make up the proposal

	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// New initiates a new proposal.  It must include all files that are part of
// the proposal.  The only acceptable file types are text, markdown and PNG.
type New struct {
	Challenge string `json:"challenge"` // Random challenge
	Name      string `json:"name"`      // Suggested short proposal name
	Files     []File `json:"files"`     // Files that make up the proposal
}

// NewReply returns the CensorshipRecord that is associated with a valid
// proposal.  A valid proposal is not always going to be published.
type NewReply struct {
	Response         string           `json:"response"` // Challenge response
	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// GetUnvetted requests an unvetted proposal from the server.
type GetUnvetted struct {
	Challenge string `json:"challenge"` // Random challenge
	Token     string `json:"token"`     // Censorship token
}

// GetUnvettedReply returns an unvetted proposal.  It retrieves the censorship
// record and the actual files.
type GetUnvettedReply struct {
	Response string         `json:"response"` // Challenge response
	Proposal ProposalRecord `json:"proposalrecord"`
}

// GetVetted requests a vetted proposal from the server.
type GetVetted struct {
	Challenge string `json:"challenge"` // Random challenge
	Token     string `json:"token"`     // Censorship token
}

// GetVettedReply returns a vetted proposal.  It retrieves the censorship
// record and the latest files in the proposal.
type GetVettedReply struct {
	Response string         `json:"response"` // Challenge response
	Proposal ProposalRecord `json:"proposalrecord"`
}

// SetUnvettedStatus updates the status of an unvetted proposal.  This is used
// to either promote a proposal to the public viewable repository or to censor
// it.
type SetUnvettedStatus struct {
	Challenge string  `json:"challenge"` // Random challenge
	Token     string  `json:"token"`     // Censorship token
	Status    StatusT `json:"status"`    // Update unvetted status of proposal
}

// SetUnvettedStatus is a response to a SetUnvettedStatus.  The status field
// may be different than the status that was requested.  This should only
// happen when the command fails.
type SetUnvettedStatusReply struct {
	Response string  `json:"response"` // Challenge response
	Status   StatusT `json:"status"`   // Actual status, may differ from request
}

//type UpdateUnvetted struct {
//	Challenge string `json:"challenge"` // Random challenge
//	Token     string `json:"token"`     // Censorship token
//	Files     []File `json:"files"`     // Files that make up the proposal
//}
//
//type UpdateUnvetted struct {
//	Challenge string `json:"challenge"` // Random challenge
//	Token     string `json:"token"`     // Censorship token
//}

// Inventory sends an (expensive and therefore authenticated) inventory request
// for vetted proposals (master branch) and branches (censored, unpublished etc)
// proposals.  This is a very expensive call and should be only issued at start
// of day.  The client should cache the reply.
// The IncludeFiles flag indicates if the records contain the proposal payload
// as well.  This can quickly become very large and should only be used when
// recovering the client side.
type Inventory struct {
	Challenge     string `json:"challenge"`     // Random challenge
	IncludeFiles  bool   `json:"includefiles"`  // Include files in records
	VettedCount   uint   `json:"vettedcount"`   // Last N vetted proposals
	BranchesCount uint   `json:"branchescount"` // Last N branches (censored, new etc)
}

// InventoryReply returns vetted and branch proposal censorship records.  If
// the Inventory command had IncludeFiles set to true the returned
// ProposalRecords will also include the proposal files.  This obviously
// enlarges the payload size and should therefore be used only in disaster
// recovery scenarios.
type InventoryReply struct {
	Response string           `json:"response"` // Challenge response
	Vetted   []ProposalRecord `json:"vetted"`   // Last N vetted proposals
	Branches []ProposalRecord `json:"branches"` // Last N branches (censored, new etc)
}
