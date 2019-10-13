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
	"github.com/decred/politeia/decredplugin"
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
	mdStreamDCCGeneral           = 5 // General DCC metadata
	mdStreamDCCStatusChanges     = 6 // DCC status changes
	mdStreamDCCSupportOpposition = 7 // DCC support/opposition changes

	// Metadata stream struct versions
	backendDCCMetadataVersion                  = 1
	backendDCCStatusChangeVersion              = 1
	backendDCCSupposeOppositionMetadataVersion = 1

	supportString = "aye"
	opposeString  = "nay"
)

var (
	validSponsorStatement = regexp.MustCompile(createSponsorStatementRegex())

	// The valid contractor
	invalidDCCContractorType = map[cms.ContractorTypeT]bool{
		cms.ContractorTypeNominee: true,
		cms.ContractorTypeInvalid: true,
	}

	// This covers the possible valid status transitions for any dcc.
	// Currentyly, this only applies to active DCC's.  In the future there will
	// be more options with the addition of Debated DCC's.
	validDCCStatusTransitions = map[cms.DCCStatusT][]cms.DCCStatusT{
		// Active DCC's may only be approved or rejected.
		cms.DCCStatusActive: {
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

	cmsUser, err := p.getCMSUserByID(u.ID.String())
	if err != nil {
		return nil, err
	}

	// Ensure that the user is authorized to create DCCs
	if _, ok := invalidDCCContractorType[cmsUser.ContractorType]; ok {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidUserDCC,
		}
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
		Reason:    "new dcc",
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
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDSizeExceededPolicy,
		}
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
	if nomineeUser.ContractorType != cms.ContractorTypeNominee &&
		dcc.Type == cms.DCCTypeIssuance {
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

	// Check to see that ContractorType is valid for any issuance
	// DCC Proposal
	if dcc.Type == cms.DCCTypeIssuance &&
		dcc.ContractorType != cms.ContractorTypeDirect &&
		dcc.ContractorType != cms.ContractorTypeSubContractor {
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDCCContractorType,
		}
	}
	// Append digest to array for merkle root calculation
	digest := util.Digest(data)
	var d [sha256.Size]byte
	copy(d[:], digest)

	var hashes []*[sha256.Size]byte
	hashes = append(hashes, &d)

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
	Signature      string         `json:"signature"`      // Signature of Token + NewStatus + Reason
}

// backendDCCSupportOppositionMetadata represents the general metadata for a DCC
// Support/Opposition 'vote' for a given DCC proposal.
type backendDCCSupportOppositionMetadata struct {
	Version   uint64 `json:"version"`   // Version of the struct
	Timestamp int64  `json:"timestamp"` // Last update of invoice
	PublicKey string `json:"publickey"` // Key used for signature
	Vote      string `json:"vote"`      // Vote for support/opposition
	Signature string `json:"signature"` // Signature of Token + Vote
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

// encodeBackendDCCSupportOppositionMetadata encodes a backendDCCSupportOppositionMetadata into a JSON
// byte slice.
func encodeBackendDCCSupportOppositionMetadata(md backendDCCSupportOppositionMetadata) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendDCCSupportOppositionMetadata decodes a JSON byte slice into a
// backendDCCSupportOppositionMetadata.
func decodeBackendDCCSupportOppositionMetadata(payload []byte) ([]backendDCCSupportOppositionMetadata, error) {
	var md []backendDCCSupportOppositionMetadata

	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var m backendDCCSupportOppositionMetadata
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
	// Get dcc from cache
	r, err := p.cache.Record(token)
	if err != nil {
		return nil, err
	}
	i := convertDCCFromCache(*r)

	// Get user IDs of support/oppose pubkeys
	supportUserIDs := make([]string, 0, len(i.SupportUserIDs))
	opposeUserIDs := make([]string, 0, len(i.OppositionUserIDs))
	for _, v := range i.SupportUserIDs {
		// Fill in userID and username fields
		u, err := p.db.UserGetByPubKey(v)
		if err != nil {
			log.Errorf("getDCC: getUserByPubKey: token:%v "+
				"pubKey:%v err:%v", token, v, err)
		} else {
			supportUserIDs = append(supportUserIDs, u.ID.String())
		}
	}
	for _, v := range i.OppositionUserIDs {
		// Fill in userID and username fields
		u, err := p.db.UserGetByPubKey(v)
		if err != nil {
			log.Errorf("getDCC: getUserByPubKey: token:%v "+
				"pubKey:%v err:%v", token, v, err)
		} else {
			opposeUserIDs = append(opposeUserIDs, u.ID.String())
		}
	}
	i.SupportUserIDs = supportUserIDs
	i.OppositionUserIDs = opposeUserIDs

	// Fill in userID and username fields
	u, err := p.db.UserGetByPubKey(i.PublicKey)
	if err != nil {
		log.Errorf("getDCC: getUserByPubKey: token:%v "+
			"pubKey:%v err:%v", token, i.PublicKey, err)
	} else {
		i.SponsorUserID = u.ID.String()
		i.SponsorUsername = u.Username
	}
	return &i, nil
}

func (p *politeiawww) processDCCDetails(gd cms.DCCDetails) (*cms.DCCDetailsReply, error) {
	log.Tracef("processDCCDetails: %v", gd.Token)

	dcc, err := p.getDCC(gd.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusDCCNotFound,
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

func (p *politeiawww) processSupportOpposeDCC(sd cms.SupportOpposeDCC, u *user.User) (*cms.SupportOpposeDCCReply, error) {
	log.Tracef("processSupportOpposeDCC: %v %v", sd.Token, u.ID)

	// The submitted Vote in the request must either be "aye" or "nay"
	if sd.Vote != supportString && sd.Vote != opposeString {
		return nil, www.UserError{
			ErrorCode:    cms.ErrorStatusInvalidSupportOppose,
			ErrorContext: []string{"support string not aye or nay"},
		}
	}

	// Validate signature
	msg := fmt.Sprintf("%v%v", sd.Token, sd.Vote)
	err := validateSignature(sd.PublicKey, sd.Signature, msg)
	if err != nil {
		return nil, err
	}

	dcc, err := p.getDCC(sd.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusDCCNotFound,
			}
		}
		return nil, err
	}
	// Check to make sure the user has not SupportOpposeed or Opposed this DCC yet
	if stringInSlice(dcc.SupportUserIDs, u.ID.String()) ||
		stringInSlice(dcc.OppositionUserIDs, u.ID.String()) {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusDuplicateSupportOppose,
		}
	}

	// Check to make sure the user is not the author of the DCC.
	if dcc.SponsorUserID == u.ID.String() {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusUserIsAuthor,
		}
	}

	// Check to make sure that the DCC is still active
	if dcc.Status != cms.DCCStatusActive {
		return nil, www.UserError{
			ErrorCode:    cms.ErrorStatusWrongDCCStatus,
			ErrorContext: []string{"dcc status must be active"},
		}
	}

	cmsUser, err := p.getCMSUserByID(u.ID.String())
	if err != nil {
		return nil, err
	}

	// Ensure that the user is authorized to support/oppose DCCs
	if _, ok := invalidDCCContractorType[cmsUser.ContractorType]; ok {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidUserDCC,
		}
	}

	// Create the change record.
	c := backendDCCSupportOppositionMetadata{
		Version:   backendDCCSupposeOppositionMetadataVersion,
		PublicKey: sd.PublicKey,
		Timestamp: time.Now().Unix(),
		Vote:      sd.Vote,
		Signature: sd.Signature,
	}
	blob, err := encodeBackendDCCSupportOppositionMetadata(c)
	if err != nil {
		return nil, err
	}

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pdCommand := pd.UpdateVettedMetadata{
		Challenge: hex.EncodeToString(challenge),
		Token:     sd.Token,
		MDAppend: []pd.MetadataStream{
			{
				ID:      mdStreamDCCSupportOpposition,
				Payload: string(blob),
			},
		},
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		pd.UpdateVettedMetadataRoute, pdCommand)
	if err != nil {
		return nil, err
	}

	var pdReply pd.UpdateVettedMetadataReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal UpdateVettedMetadataReply: %v",
			err)
	}

	// Verify the UpdateVettedMetadata challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	return &cms.SupportOpposeDCCReply{}, nil
}

func stringInSlice(arr []string, str string) bool {
	for _, s := range arr {
		if str == s {
			return true
		}
	}

	return false
}

// processNewCommentDCC sends a new comment decred plugin command to politeaid
// then fetches the new comment from the cache and returns it.
func (p *politeiawww) processNewCommentDCC(nc www.NewComment, u *user.User) (*www.NewCommentReply, error) {
	log.Tracef("processNewCommentDCC: %v %v", nc.Token, u.ID)

	// Validate comment
	err := validateComment(nc)
	if err != nil {
		return nil, err
	}

	// Ensure the public key is the user's active key
	if nc.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := nc.Token + nc.ParentID + nc.Comment
	err = validateSignature(nc.PublicKey, nc.Signature, msg)
	if err != nil {
		return nil, err
	}

	cmsUser, err := p.getCMSUserByID(u.ID.String())
	if err != nil {
		return nil, err
	}

	// Ensure that the user is authorized to comment on a DCCs
	if _, ok := invalidDCCContractorType[cmsUser.ContractorType]; ok {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidUserDCC,
		}
	}

	dcc, err := p.getDCC(nc.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusDCCNotFound,
			}
		}
		return nil, err
	}

	// Check to make sure that dcc isn't already approved.
	if dcc.Status != cms.DCCStatusActive {
		return nil, www.UserError{
			ErrorCode:    cms.ErrorStatusWrongDCCStatus,
			ErrorContext: []string{"dcc status must be active"},
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	dnc := convertNewCommentToDecredPlugin(nc)
	payload, err := decredplugin.EncodeNewComment(dnc)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdNewComment,
		CommandID: decredplugin.CmdNewComment,
		Payload:   string(payload),
	}

	// Send polieiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	ncr, err := decredplugin.DecodeNewCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	// Get comment from cache
	c, err := p.getComment(nc.Token, ncr.CommentID)
	if err != nil {
		return nil, fmt.Errorf("getComment: %v", err)
	}

	return &www.NewCommentReply{
		Comment: *c,
	}, nil
}

// processDCCComments returns all comments for a given dcc. If the user is
// logged in the user's last access time for the given comments will also be
// returned.
func (p *politeiawww) processDCCComments(token string, u *user.User) (*www.GetCommentsReply, error) {
	log.Tracef("processDCCComment: %v", token)

	// Fetch dcc comments from cache
	c, err := p.getDCCComments(token)
	if err != nil {
		return nil, err
	}

	// Get the last time the user accessed these comments. This is
	// a public route so a user may not exist.
	var accessTime int64
	if u != nil {
		if u.ProposalCommentsAccessTimes == nil {
			u.ProposalCommentsAccessTimes = make(map[string]int64)
		}
		accessTime = u.ProposalCommentsAccessTimes[token]
		u.ProposalCommentsAccessTimes[token] = time.Now().Unix()
		err = p.db.UserUpdate(*u)
		if err != nil {
			return nil, err
		}
	}

	return &www.GetCommentsReply{
		Comments:   c,
		AccessTime: accessTime,
	}, nil
}

func (p *politeiawww) getDCCComments(token string) ([]www.Comment, error) {
	log.Tracef("getDCCComments: %v", token)

	dc, err := p.decredGetComments(token)
	if err != nil {
		return nil, fmt.Errorf("decredGetComments: %v", err)
	}

	// Convert comments and fill in author info.
	comments := make([]www.Comment, 0, len(dc))
	for _, v := range dc {
		c := convertCommentFromDecred(v)
		u, err := p.db.UserGetByPubKey(c.PublicKey)
		if err != nil {
			log.Errorf("getDCCComments: UserGetByPubKey: "+
				"token:%v commentID:%v pubKey:%v err:%v",
				token, c.CommentID, c.PublicKey, err)
		} else {
			c.UserID = u.ID.String()
			c.Username = u.Username
		}
		comments = append(comments, c)
	}

	return comments, nil
}

func (p *politeiawww) processSetDCCStatus(sds cms.SetDCCStatus, u *user.User) (*cms.SetDCCStatusReply, error) {
	log.Tracef("processSetDCCStatus: %v", u.PublicKey())

	// Ensure the provided public key is the user's active key.
	if sds.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}
	// Validate signature
	msg := fmt.Sprintf("%v%v%v", sds.Token, int(sds.Status), sds.Reason)
	err := validateSignature(sds.PublicKey, sds.Signature, msg)
	if err != nil {
		return nil, err
	}

	dcc, err := p.getDCC(sds.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusDCCNotFound,
			}
		}
		return nil, err
	}

	err = validateDCCStatusTransition(dcc.Status, sds.Status, sds.Reason)
	if err != nil {
		return nil, err
	}

	// Create the change record.
	c := backendDCCStatusChange{
		Version:        backendDCCStatusChangeVersion,
		AdminPublicKey: u.PublicKey(),
		Timestamp:      time.Now().Unix(),
		NewStatus:      sds.Status,
		Reason:         sds.Reason,
		Signature:      sds.Signature,
	}
	blob, err := encodeBackendDCCStatusChange(c)
	if err != nil {
		return nil, err
	}

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pdCommand := pd.UpdateVettedMetadata{
		Challenge: hex.EncodeToString(challenge),
		Token:     sds.Token,
		MDAppend: []pd.MetadataStream{
			{
				ID:      mdStreamDCCStatusChanges,
				Payload: string(blob),
			},
		},
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		pd.UpdateVettedMetadataRoute, pdCommand)
	if err != nil {
		return nil, err
	}

	var pdReply pd.UpdateVettedMetadataReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal UpdateVettedMetadataReply: %v",
			err)
	}

	// Verify the UpdateVettedMetadata challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	dbDCC, err := p.cmsDB.DCCByToken(sds.Token)
	if err != nil {
		return nil, err
	}
	dbDCC.Status = sds.Status
	dbDCC.StatusChangeReason = sds.Reason

	// Update cmsdb
	err = p.cmsDB.UpdateDCC(dbDCC)
	if err != nil {
		return nil, err
	}

	// Only do further processing if it was an approved DCC
	if sds.Status == cms.DCCStatusApproved {
		switch dcc.DCC.Type {
		case cms.DCCTypeIssuance:
			// Do DCC user Issuance processing
			err := p.issuanceDCCUser(dcc.DCC.NomineeUserID, u.ID.String(),
				int(dcc.DCC.Domain), int(dcc.DCC.ContractorType))
			if err != nil {
				return nil, err
			}
		case cms.DCCTypeRevocation:
			// Do DCC user Revocation processing
			err = p.revokeDCCUser(dcc.DCC.NomineeUserID)
			if err != nil {
				return nil, err
			}
		}
	}

	return &cms.SetDCCStatusReply{}, nil
}

func validateDCCStatusTransition(oldStatus cms.DCCStatusT, newStatus cms.DCCStatusT, reason string) error {
	validStatuses, ok := validDCCStatusTransitions[oldStatus]
	if !ok {
		log.Debugf("status not supported: %v", oldStatus)
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDCCStatusTransition,
		}
	}

	if !dccStatusInSlice(validStatuses, newStatus) {
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDCCStatusTransition,
		}
	}

	if (newStatus == cms.DCCStatusApproved ||
		newStatus == cms.DCCStatusRejected) && reason == "" {
		return www.UserError{
			ErrorCode: cms.ErrorStatusReasonNotProvided,
		}
	}
	return nil
}

func dccStatusInSlice(arr []cms.DCCStatusT, status cms.DCCStatusT) bool {
	for _, s := range arr {
		if status == s {
			return true
		}
	}

	return false
}
