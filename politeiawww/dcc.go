// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/cache"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

const (
	// dccFile contains the file name of the dcc file
	dccFile = "dcc.json"

	// politeiad dcc record metadata streams
	mdStreamDCCGeneral       = 5 // General DCC metadata
	mdStreamDCCStatusChanges = 6 // DCC status changes

	// Metadata stream struct versions
	backendDCCMetadataVersion     = 1
	backendDCCStatusChangeVersion = 1

	sponsorString = "aye"
	opposeString  = "nay"
)

var (
	validSponsorStatement     = regexp.MustCompile(createSponsorStatementRegex())
	validDCCStatusTransitions = map[cms.DCCStatusT][]cms.DCCStatusT{
		cms.DCCStatusActive: {
			cms.DCCStatusApproved,
			cms.DCCStatusSupported,
			cms.DCCStatusRejected,
			cms.DCCStatusDebate,
		},
		cms.DCCStatusSupported: {
			cms.DCCStatusApproved,
			cms.DCCStatusRejected,
		},
	}
)

// createSponsorStatementRegex generates a regex based on the policy supplied for
// valid characters sponsor statement.
func createSponsorStatementRegex() string {
	var buf bytes.Buffer
	buf.WriteString("^[")

	for _, supportedChar := range cms.PolicySponsorStatementSupportedChars {
		if len(supportedChar) > 1 {
			buf.WriteString(supportedChar)
		} else {
			buf.WriteString(`\` + supportedChar)
		}
	}
	buf.WriteString("]{")
	buf.WriteString(strconv.Itoa(cms.PolicyMinSponsorStatementLength) + ",")
	buf.WriteString(strconv.Itoa(cms.PolicyMaxSponsorStatementLength) + "}$")

	return buf.String()
}

func (p *politeiawww) processNewDCC(nd cms.NewDCC, u *user.User) (*cms.NewDCCReply, error) {
	reply := &cms.NewDCCReply{}

	err := p.validateDCC(nd, u)
	if err != nil {
		return nil, err
	}

	m := backendDCCMetadata{
		Version:   backendDCCMetadataVersion,
		Timestamp: time.Now().Unix(),
		PublicKey: nd.PublicKey,
		Signature: nd.Signature,
	}
	md, err := encodeBackendDCCMetadata(m)
	if err != nil {
		return nil, err
	}

	sc := backendDCCStatusChange{
		Version:   backendDCCStatusChangeVersion,
		Timestamp: time.Now().Unix(),
		NewStatus: cms.DCCStatusActive,
	}
	scb, err := encodeBackendDCCStatusChange(sc)
	if err != nil {
		return nil, err
	}

	// Create expected []www.File from single dcc.json file
	files := make([]www.File, 0, 1)
	files = append(files, nd.File)

	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	n := pd.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata: []pd.MetadataStream{
			{
				ID:      mdStreamDCCGeneral,
				Payload: string(md),
			},
			{
				ID:      mdStreamDCCStatusChanges,
				Payload: string(scb),
			},
		},
		Files: convertPropFilesFromWWW(files),
	}

	// Send the newrecord politeiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.NewRecordRoute, n)
	if err != nil {
		return nil, err
	}

	log.Infof("Submitted issuance nomination: %v", u.Username)
	for k, f := range n.Files {
		log.Infof("%02v: %v %v", k, f.Name, f.Digest)
	}

	// Handle newRecord response
	var pdReply pd.NewRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal NewDCCReply: %v", err)
	}

	// Verify NewRecord challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	// Change politeiad record status to public. DCCs
	// do not need to be reviewed before becoming public.
	// An admin signature is not included for this reason.
	c := MDStreamChanges{
		Version:   VersionMDStreamChanges,
		Timestamp: time.Now().Unix(),
		NewStatus: pd.RecordStatusPublic,
	}
	blob, err := encodeMDStreamChanges(c)
	if err != nil {
		return nil, err
	}

	challenge, err = util.Random(pd.ChallengeSize)
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

	var pdSetUnvettedStatusReply pd.SetUnvettedStatusReply
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
	// Submit issuance to cmsdb

	dccRec, err := convertRecordToDatabaseDCC(r)
	if err != nil {
		return nil, err
	}

	err = p.cmsDB.NewDCC(dccRec)
	if err != nil {
		return nil, err
	}

	cr := convertPropCensorFromPD(pdReply.CensorshipRecord)

	reply.CensorshipRecord = cr
	return reply, nil
}

func (p *politeiawww) validateDCC(nd cms.NewDCC, u *user.User) error {

	// Obtain signature
	sig, err := util.ConvertSignature(nd.Signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Verify public key
	if u.PublicKey() != nd.PublicKey {
		fmt.Println(u.PublicKey(), nd.PublicKey)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	pk, err := identity.PublicIdentityFromBytes(u.ActiveIdentity().Key[:])
	if err != nil {
		return err
	}

	// Check for at least 1 a non-empty payload.
	if nd.File.Payload == "" {
		return www.UserError{
			ErrorCode: www.ErrorStatusProposalMissingFiles,
		}
	}

	// Check that the file number policy is followed.
	var (
		jsonExceedsMaxSize bool
		hashes             []*[sha256.Size]byte
	)

	v := nd.File

	if v.Name != dccFile {
		return www.UserError{
			ErrorCode: cms.ErrorStatusMalformedDCCFile,
		}
	}

	data, err := base64.StdEncoding.DecodeString(v.Payload)
	if err != nil {
		return err
	}
	if len(data) > cms.PolicyMaxMDSize {
		jsonExceedsMaxSize = true
	}

	// Check to see if the data can be parsed properly into DCCInput
	// struct.
	var dcc cms.DCCInput
	if err := json.Unmarshal(data, &dcc); err != nil {
		return www.UserError{
			ErrorCode: cms.ErrorStatusMalformedDCCFile,
		}
	}
	// Check UserID of Nominee
	nomineeUser, err := p.getCMSUserByID(dcc.NomineeUserID)
	if err != nil {
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDCCNominee,
		}
	}
	if nomineeUser.ContractorType != cms.ContractorTypeNominee {
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDCCNominee,
		}
	}

	sponsorUser, err := p.getCMSUserByID(u.ID.String())
	if err != nil {
		return err
	}

	// Check that domains match
	if sponsorUser.Domain != dcc.Domain {
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvalidNominatingDomain,
		}
	}

	// Validate sponsor statement input
	statement := formatSponsorStatement(dcc.SponsorStatement)
	if !validateSponsorStatement(statement) {
		return www.UserError{
			ErrorCode: cms.ErrorStatusMalformedSponsorStatement,
		}
	}

	// Append digest to array for merkle root calculation
	digest := util.Digest(data)
	var d [sha256.Size]byte
	copy(d[:], digest)
	hashes = append(hashes, &d)

	if jsonExceedsMaxSize {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDSizeExceededPolicy,
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

// formatSponsorStatement normalizes a sponsor statement without leading and
// trailing spaces.
func formatSponsorStatement(statement string) string {
	return strings.TrimSpace(statement)
}

// validateSponsorStatement verifies that a field filled out in invoice.json is
// valid
func validateSponsorStatement(statement string) bool {
	if statement != formatSponsorStatement(statement) {
		log.Tracef("validateSponsorStatement: not normalized: %s %s",
			statement, formatSponsorStatement(statement))
		return false
	}
	if len(statement) > cms.PolicyMaxSponsorStatementLength ||
		len(statement) < cms.PolicyMinSponsorStatementLength {
		log.Tracef("validateSponsorStatement: not within bounds: have %v expected > %v < %v",
			len(statement), cms.PolicyMaxSponsorStatementLength,
			cms.PolicyMinSponsorStatementLength)
		return false
	}
	if !validSponsorStatement.MatchString(statement) {
		log.Tracef("validateSponsorStatement: not valid: %s %s",
			statement, validSponsorStatement.String())
		return false
	}
	return true
}

// backendDCCMetadata represents the general metadata for a DCC and is
// stored in the metadata stream mdStreamDCCGeneral in politeiad.
type backendDCCMetadata struct {
	Version   uint64 `json:"version"`   // Version of the struct
	Timestamp int64  `json:"timestamp"` // Last update of invoice
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
}

// backendDCCStatusChange represents the metadata for any status change that
// occurs to a patricular DCC issuance or revocation.
type backendDCCStatusChange struct {
	Version        uint           `json:"version"`        // Version of the struct
	AdminPublicKey string         `json:"adminpublickey"` // Identity of the administrator
	NewStatus      cms.DCCStatusT `json:"newstatus"`      // Status
	Reason         string         `json:"reason"`         // Reason
	Timestamp      int64          `json:"timestamp"`      // Timestamp of the change
}

// encodeBackendDCCMetadata encodes a backendDCCMetadata into a JSON
// byte slice.
func encodeBackendDCCMetadata(md backendDCCMetadata) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendDCCMetadata decodes a JSON byte slice into a
// backendDCCMetadata.
func decodeBackendDCCMetadata(payload []byte) (*backendDCCMetadata, error) {
	var md backendDCCMetadata

	err := json.Unmarshal(payload, &md)
	if err != nil {
		return nil, err
	}

	return &md, nil
}

// encodeBackendDCCStatusChange encodes a backendDCCStatusChange into a
// JSON byte slice.
func encodeBackendDCCStatusChange(md backendDCCStatusChange) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendDCCStatusChanges decodes a JSON byte slice into a slice of
// backendDCCStatusChanges.
func decodeBackendDCCStatusChanges(payload []byte) ([]backendDCCStatusChange, error) {
	var md []backendDCCStatusChange

	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var m backendDCCStatusChange
		err := d.Decode(&m)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		md = append(md, m)
	}

	return md, nil
}

// getDCC gets the most recent verions of the given DCC from the cache
// then fills in any missing user fields before returning the DCC record.
func (p *politeiawww) getDCC(token string) (*cms.DCCRecord, error) {
	// Get invoice from cache
	r, err := p.cache.Record(token)
	if err != nil {
		return nil, err
	}
	i := convertDCCFromCache(*r)

	// Fill in userID and username fields
	u, err := p.db.UserGetByPubKey(i.PublicKey)
	if err != nil {
		log.Errorf("getDCC: getUserByPubKey: token:%v "+
			"pubKey:%v err:%v", token, i.PublicKey, err)
	} else {
		i.SponsorUserID = u.ID.String()
		i.SponsorUsername = u.Username
	}
	support, oppose, err := p.getDCCSupportOppositionComments(token)
	if err != nil {
		log.Errorf("getDCC: %v", err)
	}
	i.SupportUserIDs = support
	i.OppositionUserIDs = oppose
	return &i, nil
}

func (p *politeiawww) getDCCSupportOppositionComments(token string) ([]string, []string, error) {
	log.Tracef("getDCCSupportOpposition: %v", token)

	dc, err := p.decredGetComments(token)
	if err != nil {
		return nil, nil, fmt.Errorf("decredGetComments: %v", err)
	}

	support := make([]string, 0, len(dc))
	oppose := make([]string, 0, len(dc))
	for _, v := range dc {
		c := convertCommentFromDecred(v)
		u, err := p.db.UserGetByPubKey(c.PublicKey)
		if err != nil {
			log.Errorf("getDCCSupportOpposition: UserGetByPubKey: "+
				"token:%v commentID:%v pubKey:%v err:%v",
				token, c.CommentID, c.PublicKey, err)
		}
		if c.Comment == sponsorString {
			support = append(support, u.ID.String())
		} else if c.Comment == opposeString {
			oppose = append(support, u.ID.String())
		}
	}

	return support, oppose, nil
}

func (p *politeiawww) processDCCDetails(gd cms.DCCDetails) (*cms.DCCDetailsReply, error) {
	log.Tracef("processDCCDetails: %v", gd.Token)

	dcc, err := p.getDCC(gd.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}
	reply := &cms.DCCDetailsReply{
		DCC: *dcc,
	}
	return reply, nil
}

func (p *politeiawww) processGetDCCs(gds cms.GetDCCs) (*cms.GetDCCsReply, error) {
	log.Tracef("processGetDCCs: %v", gds.Status)

	var dbDCCs []*cmsdatabase.DCC
	var err error
	switch {
	case gds.Status != 0:
		dbDCCs, err = p.cmsDB.DCCsByStatus(int(gds.Status))
		if err != nil {
			return nil, err
		}

	default:
		dbDCCs, err = p.cmsDB.DCCsAll()
		if err != nil {
			return nil, err
		}
	}
	dccs := make([]cms.DCCRecord, 0, len(dbDCCs))

	for _, v := range dbDCCs {
		dcc, err := p.getDCC(v.Token)
		if err != nil {
			return nil, err
		}
		dccs = append(dccs, *dcc)
	}

	return &cms.GetDCCsReply{
		DCCs: dccs,
	}, nil
}
