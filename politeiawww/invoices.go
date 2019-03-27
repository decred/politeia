// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/cache"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

const (
	// invoiceFile contains the file name of the invoice file
	invoiceFile = "invoice.json"

	BackendInvoiceMetadataVersion = 1
	BackendInvoiceMDChangeVersion = 1
)

// processNewInvoice tries to submit a new proposal to politeiad.
func (p *politeiawww) processNewInvoice(ni cms.NewInvoice, u *user.User) (*cms.NewInvoiceReply, error) {
	log.Tracef("processNewInvoice")

	err := validateInvoice(ni, u)
	if err != nil {
		return nil, err
	}

	name := strconv.Itoa(int(ni.Year)) + strconv.Itoa(int(ni.Month)) + u.Username

	md, err := encodeBackendInvoiceMetadata(BackendInvoiceMetadata{
		Version:   BackendInvoiceMetadataVersion,
		Timestamp: time.Now().Unix(),
		Name:      name,
		PublicKey: ni.PublicKey,
		Signature: ni.Signature,
		Month:     ni.Month,
		Year:      ni.Year,
	})
	if err != nil {
		return nil, err
	}

	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	n := pd.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata: []pd.MetadataStream{{
			ID:      mdStreamGeneral,
			Payload: string(md),
		}},
		Files: convertPropFilesFromWWW(ni.Files),
	}

	// Handle test case
	if p.test {
		tokenBytes, err := util.Random(pd.TokenSize)
		if err != nil {
			return nil, err
		}

		testReply := pd.NewRecordReply{
			CensorshipRecord: pd.CensorshipRecord{
				Token: hex.EncodeToString(tokenBytes),
			},
		}

		return &cms.NewInvoiceReply{
			CensorshipRecord: convertPropCensorFromPD(testReply.CensorshipRecord),
		}, nil
	}

	// Send the newrecord politeiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.NewRecordRoute, n)
	if err != nil {
		return nil, err
	}

	log.Infof("Submitted invoice name: %v", name)
	for k, f := range n.Files {
		log.Infof("%02v: %v %v", k, f.Name, f.Digest)
	}

	// Handle newRecord response
	var pdReply pd.NewRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal NewInvoiceReply: %v", err)
	}

	// Verify NewRecord challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	// Create change record since we are immediately considering this Vetted and
	// New Invoice Status.
	changes := BackendInvoiceMDChange{
		Version:   BackendInvoiceMDChangeVersion,
		Timestamp: time.Now().Unix(),
		NewStatus: cms.InvoiceStatusNew,
	}

	var pdSetUnvettedStatusReply pd.SetUnvettedStatusReply
	challenge, err = util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	blob, err := json.Marshal(changes)
	if err != nil {
		return nil, err
	}

	sus := pd.SetUnvettedStatus{
		Token:     pdReply.CensorshipRecord.Token,
		Status:    pd.RecordStatusPublic,
		Challenge: hex.EncodeToString(challenge),
		MDAppend: []pd.MetadataStream{
			{
				ID:      mdStreamChanges,
				Payload: string(blob),
			},
		},
	}

	// Send SetUnvettedStatus request to politeiad
	responseBody, err = p.makeRequest(http.MethodPost,
		pd.SetUnvettedStatusRoute, sus)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(responseBody, &pdSetUnvettedStatusReply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal SetUnvettedStatusReply: %v",
			err)
	}

	// Verify the SetUnvettedStatus challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge,
		pdSetUnvettedStatusReply.Response)
	if err != nil {
		return nil, err
	}

	r := pd.Record{
		Metadata:         n.Metadata,
		Files:            n.Files,
		CensorshipRecord: pdReply.CensorshipRecord,
	}
	ir, err := convertRecordToDatabaseInvoice(r)
	if err != nil {
		return nil, err
	}
	// Set UserID for current user
	ir.UserID = u.ID.String()
	ir.Status = cms.InvoiceStatusNew

	err = p.cmsDB.NewInvoice(ir)
	if err != nil {
		return nil, err
	}
	cr := convertPropCensorFromPD(pdReply.CensorshipRecord)

	// Fire off new proposal event
	p.fireEvent(EventTypeProposalSubmitted,
		EventDataProposalSubmitted{
			CensorshipRecord: &cr,
			ProposalName:     name,
			User:             u,
		},
	)

	return &cms.NewInvoiceReply{
		CensorshipRecord: cr,
	}, nil
}

func validateInvoice(ni cms.NewInvoice, u *user.User) error {
	log.Tracef("validateInvoice")

	// Obtain signature
	sig, err := util.ConvertSignature(ni.Signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Verify public key
	id, err := checkPublicKey(u, ni.PublicKey)
	if err != nil {
		return err
	}

	pk, err := identity.PublicIdentityFromBytes(id[:])
	if err != nil {
		return err
	}

	// Check for at least 1 markdown file with a non-empty payload.
	if len(ni.Files) == 0 || ni.Files[0].Payload == "" {
		fmt.Println(ni.Files[0].Payload)
		return www.UserError{
			ErrorCode: www.ErrorStatusProposalMissingFiles,
		}
	}

	// verify if there are duplicate names
	filenames := make(map[string]int, len(ni.Files))
	// Check that the file number policy is followed.
	var (
		numCSVs, numImages, numInvoiceFiles    int
		csvExceedsMaxSize, imageExceedsMaxSize bool
		hashes                                 []*[sha256.Size]byte
	)
	for _, v := range ni.Files {
		filenames[v.Name]++
		var (
			data []byte
			err  error
		)
		if strings.HasPrefix(v.MIME, "image/") {
			numImages++
			data, err = base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			if len(data) > www.PolicyMaxImageSize {
				imageExceedsMaxSize = true
			}
		} else {
			numCSVs++

			if v.Name == invoiceFile {
				numInvoiceFiles++
			}

			data, err = base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			if len(data) > www.PolicyMaxMDSize {
				csvExceedsMaxSize = true
			}

			// Check to see if the data can be parsed properly into InvoiceInput
			// struct.
			var invInput cms.InvoiceInput
			if err := json.Unmarshal(data, &invInput); err != nil {
				return www.UserError{
					ErrorCode: www.ErrorStatusMalformedInvoiceFile,
				}
			}

		}

		// Append digest to array for merkle root calculation
		digest := util.Digest(data)
		var d [sha256.Size]byte
		copy(d[:], digest)
		hashes = append(hashes, &d)
	}

	// verify duplicate file names
	if len(ni.Files) > 1 {
		var repeated []string
		for name, count := range filenames {
			if count > 1 {
				repeated = append(repeated, name)
			}
		}
		if len(repeated) > 0 {
			return www.UserError{
				ErrorCode:    www.ErrorStatusProposalDuplicateFilenames,
				ErrorContext: repeated,
			}
		}
	}

	// we expect one index file
	if numInvoiceFiles == 0 {
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalMissingFiles,
			ErrorContext: []string{indexFile},
		}
	}

	if numCSVs > www.PolicyMaxMDs {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDsExceededPolicy,
		}
	}

	if numImages > www.PolicyMaxImages {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxImagesExceededPolicy,
		}
	}

	if csvExceedsMaxSize {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDSizeExceededPolicy,
		}
	}

	if imageExceedsMaxSize {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxImageSizeExceededPolicy,
		}
	}

	// Note that we need validate the string representation of the merkle
	mr := merkle.Root(hashes)
	if !pk.VerifyMessage([]byte(hex.EncodeToString(mr[:])), sig) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	return nil
}

// processInvoiceDetails fetches a specific proposal version from the records
// cache and returns it.
func (p *politeiawww) processInvoiceDetails(invDetails cms.InvoiceDetails,
	user *user.User) (*cms.InvoiceDetailsReply, error) {
	log.Tracef("processInvoiceDetails")

	inv, err := p.cmsDB.InvoiceByToken(invDetails.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}
	r, err := p.cache.Record(invDetails.Token)
	if err != nil {
		return nil, err
	}

	invRec, err := convertDatabaseInvoiceToInvoiceRecord(*inv)
	if err != nil {
		return nil, err
	}
	invRec.Username = p.getUsernameById(invRec.UserID)

	// Get raw record information from d cache
	pr := convertPropFromCache(*r)

	invRec.Files = pr.Files
	invRec.CensorshipRecord = pr.CensorshipRecord
	invRec.Signature = pr.Signature

	// Setup reply
	reply := cms.InvoiceDetailsReply{
		Invoice: *invRec,
	}

	return &reply, nil
}

// BackendInvoiceMetadata is the metadata for Records into politeiad.
type BackendInvoiceMetadata struct {
	Version   uint64 `json:"version"` // BackendInvoiceMetadata version
	Month     uint16 `json:"month"`
	Year      uint16 `json:"year"`
	Timestamp int64  `json:"timestamp"` // Last update of invoice
	PublicKey string `json:"publickey"` // Key used for signature.
	Signature string `json:"signature"` // Signature of merkle root
	Name      string `json:"name"`      // Generated invoice name
}

// BackendInvoiceMDChange is the metadata for updating Records on politeiad.
type BackendInvoiceMDChange struct {
	Version        uint               `json:"version"`        // Version of the struct
	AdminPublicKey string             `json:"adminpublickey"` // Identity of the administrator
	NewStatus      cms.InvoiceStatusT `json:"newstatus"`      // Status
	Reason         *string            `json:"reason"`         // Reason
	Timestamp      int64              `json:"timestamp"`      // Timestamp of the change
}

// encodeBackendInvoiceMetadata encodes BackendInvoiceMetadata into a JSON
// byte slice.
func encodeBackendInvoiceMetadata(md BackendInvoiceMetadata) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendInvoiceMetadata decodes a JSON byte slice into a
// BackendInvoiceMetadata.
func decodeBackendInvoiceMetadata(payload []byte) (*BackendInvoiceMetadata, error) {
	var md BackendInvoiceMetadata

	err := json.Unmarshal(payload, &md)
	if err != nil {
		return nil, err
	}

	return &md, nil
}

// encodeBackendInvoiceMetadata encodes BackendInvoiceMetadata into a JSON
// byte slice.
func encodeBackendInvoiceMDChange(md BackendInvoiceMDChange) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendInvoiceMetadata decodes a JSON byte slice into a
// BackendInvoiceMetadata.
func decodeBackendInvoiceMDChange(payload []byte) (*BackendInvoiceMDChange, error) {
	var md BackendInvoiceMDChange

	err := json.Unmarshal(payload, &md)
	if err != nil {
		return nil, err
	}

	return &md, nil
}
