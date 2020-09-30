// Copyright (c) 2019-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/decred/politeia/cmsplugin"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/decred/politeia/politeiawww/user"
	wwwutil "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
)

const (
	// dccFile contains the file name of the dcc file
	dccFile = "dcc.json"

	supportString = "aye"
	opposeString  = "nay"

	// DCC All User Vote Configuration
	dccVoteDuration         = 24 * 7 * time.Hour // 1 Week
	averageMonthlyMinutes   = 180 * 60           // 180 Hours * 60 Minutes
	userWeightMonthLookback = 6                  // Lookback 6 months to deteremine user voting weight
)

var (
	validSponsorStatement = regexp.MustCompile(createSponsorStatementRegex())

	// The valid contractor
	invalidDCCContractorType = map[cms.ContractorTypeT]bool{
		cms.ContractorTypeNominee: true,
		cms.ContractorTypeInvalid: true,
	}

	// This covers the possible valid status transitions for any dcc.
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
	buf.WriteString("]*$")

	return buf.String()
}

func convertRecordToDatabaseDCC(p pd.Record) (*cmsdatabase.DCC, error) {
	dbDCC := cmsdatabase.DCC{
		Files:           convertWWWFilesFromPD(p.Files),
		Token:           p.CensorshipRecord.Token,
		ServerSignature: p.CensorshipRecord.Signature,
	}

	// Decode invoice file
	for _, v := range p.Files {
		if v.Name == dccFile {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}

			var dcc cms.DCCInput
			err = json.Unmarshal(b, &dcc)
			if err != nil {
				return nil, fmt.Errorf("could not decode DCC input data: token '%v': %v",
					p.CensorshipRecord.Token, err)
			}
			dbDCC.Type = dcc.Type
			dbDCC.NomineeUserID = dcc.NomineeUserID
			dbDCC.SponsorStatement = dcc.SponsorStatement
			dbDCC.Domain = dcc.Domain
			dbDCC.ContractorType = dcc.ContractorType
		}
	}

	for _, m := range p.Metadata {
		switch m.ID {
		case mdstream.IDRecordStatusChange:
			// Ignore initial stream change since it's just the automatic change from
			// unvetted to vetted
			continue
		case mdstream.IDDCCGeneral:
			var mdGeneral mdstream.DCCGeneral
			err := json.Unmarshal([]byte(m.Payload), &mdGeneral)
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					p.Metadata, p.CensorshipRecord.Token, err)
			}

			dbDCC.TimeSubmitted = mdGeneral.Timestamp
			dbDCC.PublicKey = mdGeneral.PublicKey
			dbDCC.UserSignature = mdGeneral.Signature

		case mdstream.IDDCCStatusChange:
			sc, err := mdstream.DecodeDCCStatusChange([]byte(m.Payload))
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					m, p.CensorshipRecord.Token, err)
			}

			// We don't need all of the status changes.
			// Just the most recent one.
			for _, s := range sc {
				dbDCC.Status = s.NewStatus
				dbDCC.StatusChangeReason = s.Reason
				dbDCC.TimeReviewed = s.Timestamp
			}
		case mdstream.IDDCCSupportOpposition:
			// Support and Opposition
			so, err := mdstream.DecodeDCCSupportOpposition([]byte(m.Payload))
			if err != nil {
				log.Errorf("convertDCCFromRecord: decode md stream: "+
					"token:%v error:%v payload:%v",
					p.CensorshipRecord.Token, err, m)
				continue
			}
			supportPubkeys := make([]string, 0, len(so))
			opposePubkeys := make([]string, 0, len(so))
			// Tabulate all support and opposition
			for _, s := range so {
				if s.Vote == supportString {
					supportPubkeys = append(supportPubkeys, s.PublicKey)
				} else if s.Vote == opposeString {
					opposePubkeys = append(opposePubkeys, s.PublicKey)
				}
			}
			supports := ""
			for i, support := range supportPubkeys {
				if i != len(supportPubkeys)-1 {
					supports += support + ", "
				} else {
					supports += support
				}
			}
			dbDCC.SupportUserIDs = supports
			opposes := ""
			for i, oppose := range opposePubkeys {
				if i != len(opposePubkeys)-1 {
					opposes += oppose + ", "
				} else {
					opposes += oppose
				}
			}
			dbDCC.OppositionUserIDs = opposes
		case cmsplugin.MDStreamVoteBits:
		case cmsplugin.MDStreamVoteSnapshot:
			// Voting information available but not currently used in the database
		default:
			// Log error but proceed
			log.Errorf("convertRecordToDCC: invalid "+
				"metadata stream ID %v token %v",
				m.ID, p.CensorshipRecord.Token)
		}
	}

	return &dbDCC, nil
}

func convertDCCDatabaseToRecord(dbDCC *cmsdatabase.DCC) cms.DCCRecord {
	dccRecord := cms.DCCRecord{}

	dccRecord.DCC.Type = dbDCC.Type
	dccRecord.DCC.NomineeUserID = dbDCC.NomineeUserID
	dccRecord.DCC.SponsorStatement = dbDCC.SponsorStatement
	dccRecord.DCC.Domain = dbDCC.Domain
	dccRecord.DCC.ContractorType = dbDCC.ContractorType
	dccRecord.Status = dbDCC.Status
	dccRecord.StatusChangeReason = dbDCC.StatusChangeReason
	dccRecord.TimeSubmitted = dbDCC.TimeSubmitted
	dccRecord.TimeReviewed = dbDCC.TimeReviewed
	dccRecord.CensorshipRecord = www.CensorshipRecord{
		Token: dbDCC.Token,
	}
	dccRecord.PublicKey = dbDCC.PublicKey
	dccRecord.Signature = dbDCC.ServerSignature
	dccRecord.SponsorUserID = dbDCC.SponsorUserID
	supportUserIDs := strings.Split(dbDCC.SupportUserIDs, ",")
	cleanedSupport := make([]string, 0, len(supportUserIDs))
	for _, support := range supportUserIDs {
		cleanedSupport = append(cleanedSupport, strings.TrimSpace(support))
	}
	dccRecord.SupportUserIDs = cleanedSupport
	oppositionUserIDs := strings.Split(dbDCC.OppositionUserIDs, ",")
	cleanedOpposed := make([]string, 0, len(oppositionUserIDs))
	for _, oppose := range oppositionUserIDs {
		cleanedOpposed = append(cleanedOpposed, strings.TrimSpace(oppose))
	}
	dccRecord.OppositionUserIDs = cleanedOpposed

	return dccRecord
}

func convertDCCDatabaseFromDCCRecord(dccRecord cms.DCCRecord) cmsdatabase.DCC {
	dbDCC := cmsdatabase.DCC{}

	dbDCC.Type = dccRecord.DCC.Type
	dbDCC.NomineeUserID = dccRecord.DCC.NomineeUserID
	dbDCC.SponsorStatement = dccRecord.DCC.SponsorStatement
	dbDCC.Domain = dccRecord.DCC.Domain
	dbDCC.ContractorType = dccRecord.DCC.ContractorType
	dbDCC.Status = dccRecord.Status
	dbDCC.StatusChangeReason = dccRecord.StatusChangeReason
	dbDCC.TimeSubmitted = dccRecord.TimeSubmitted
	dbDCC.TimeReviewed = dccRecord.TimeReviewed
	dbDCC.Token = dccRecord.CensorshipRecord.Token
	dbDCC.PublicKey = dccRecord.PublicKey
	dbDCC.ServerSignature = dccRecord.Signature
	dbDCC.SponsorUserID = dccRecord.SponsorUserID
	dbDCC.Token = dccRecord.CensorshipRecord.Token

	supportUserIDs := ""
	for i, s := range dccRecord.SupportUserIDs {
		if i == 0 {
			supportUserIDs += s
		} else {
			supportUserIDs += "," + s
		}
	}
	dbDCC.SupportUserIDs = supportUserIDs

	oppositionUserIDs := ""
	for i, s := range dccRecord.OppositionUserIDs {
		if i == 0 {
			oppositionUserIDs += s
		} else {
			oppositionUserIDs += "," + s
		}
	}
	dbDCC.OppositionUserIDs = oppositionUserIDs

	return dbDCC
}

func convertCastVoteFromCMS(b cms.CastVote) cmsplugin.CastVote {
	return cmsplugin.CastVote{
		VoteBit:   b.VoteBit,
		Token:     b.Token,
		UserID:    b.UserID,
		Signature: b.Signature,
	}
}

func convertCastVoteReplyToCMS(cv *cmsplugin.CastVoteReply) *cms.CastVoteReply {
	return &cms.CastVoteReply{
		ClientSignature: cv.ClientSignature,
		Signature:       cv.Signature,
		Error:           cv.Error,
		ErrorStatus:     cv.ErrorStatus,
	}
}

func convertUserWeightToCMS(uw []cmsplugin.UserWeight) []cms.DCCWeight {
	dccWeight := make([]cms.DCCWeight, 0, len(uw))
	for _, w := range uw {
		dccWeight = append(dccWeight, cms.DCCWeight{
			UserID: w.UserID,
			Weight: w.Weight,
		})
	}
	return dccWeight
}

func convertVoteOptionResultsToCMS(vr []cmsplugin.VoteOptionResult) []cms.VoteOptionResult {
	votes := make([]cms.VoteOptionResult, 0, len(vr))
	for _, w := range vr {
		votes = append(votes, cms.VoteOptionResult{
			Option: cms.VoteOption{
				Id:          w.ID,
				Description: w.Description,
				Bits:        w.Bits,
			},
			VotesReceived: w.Votes,
		})
	}
	return votes
}
func convertCMSStartVoteToCMSVoteDetailsReply(sv cmsplugin.StartVote, svr cmsplugin.StartVoteReply) (*cms.VoteDetailsReply, error) {
	voteb, err := cmsplugin.EncodeVote(sv.Vote)
	if err != nil {
		return nil, err
	}
	userWeights := make([]string, 0, len(sv.UserWeights))
	for _, weights := range sv.UserWeights {
		userWeight := weights.UserID + "-" + strconv.Itoa(int(weights.Weight))
		userWeights = append(userWeights, userWeight)
	}
	return &cms.VoteDetailsReply{
		Version:          uint32(sv.Version),
		Vote:             string(voteb),
		PublicKey:        sv.PublicKey,
		Signature:        sv.Signature,
		StartBlockHeight: svr.StartBlockHeight,
		StartBlockHash:   svr.StartBlockHash,
		EndBlockHeight:   svr.EndHeight,
		UserWeights:      userWeights,
	}, nil
}

func convertCMSStartVoteToCMS(sv cmsplugin.StartVote) cms.StartVote {
	vote := cms.Vote{
		Token:            sv.Vote.Token,
		Mask:             sv.Vote.Mask,
		Duration:         sv.Vote.Duration,
		QuorumPercentage: sv.Vote.QuorumPercentage,
		PassPercentage:   sv.Vote.PassPercentage,
	}

	voteOptions := make([]cms.VoteOption, 0, len(sv.Vote.Options))
	for _, option := range sv.Vote.Options {
		voteOption := cms.VoteOption{
			Id:          option.Id,
			Description: option.Description,
			Bits:        option.Bits,
		}
		voteOptions = append(voteOptions, voteOption)
	}
	vote.Options = voteOptions

	return cms.StartVote{
		Vote:      vote,
		PublicKey: sv.PublicKey,
		Signature: sv.Signature,
	}
}

func convertCMSStartVoteReplyToCMS(svr cmsplugin.StartVoteReply) cms.StartVoteReply {
	return cms.StartVoteReply{
		StartBlockHeight: svr.StartBlockHeight,
		StartBlockHash:   svr.StartBlockHash,
		EndBlockHeight:   svr.EndHeight,
	}
}

func convertStartVoteToCMS(sv cms.StartVote) cmsplugin.StartVote {
	vote := cmsplugin.Vote{
		Token:            sv.Vote.Token,
		Mask:             sv.Vote.Mask,
		Duration:         sv.Vote.Duration,
		QuorumPercentage: sv.Vote.QuorumPercentage,
		PassPercentage:   sv.Vote.PassPercentage,
	}

	voteOptions := make([]cmsplugin.VoteOption, 0, len(sv.Vote.Options))
	for _, option := range sv.Vote.Options {
		voteOption := cmsplugin.VoteOption{
			Id:          option.Id,
			Description: option.Description,
			Bits:        option.Bits,
		}
		voteOptions = append(voteOptions, voteOption)
	}
	vote.Options = voteOptions

	return cmsplugin.StartVote{
		Token:     sv.Vote.Token,
		Vote:      vote,
		PublicKey: sv.PublicKey,
		Signature: sv.Signature,
	}

}

func convertPiFilesFromWWW(files []www.File) []pi.File {
	f := make([]pi.File, 0, len(files))
	for _, v := range files {
		f = append(f, pi.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}
	return f
}

func (p *politeiawww) processNewDCC(ctx context.Context, nd cms.NewDCC, u *user.User) (*cms.NewDCCReply, error) {
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

	m := mdstream.DCCGeneral{
		Version:   mdstream.VersionDCCGeneral,
		Timestamp: time.Now().Unix(),
		PublicKey: nd.PublicKey,
		Signature: nd.Signature,
	}
	md, err := mdstream.EncodeDCCGeneral(m)
	if err != nil {
		return nil, err
	}

	sc := mdstream.DCCStatusChange{
		Version:   mdstream.VersionDCCStatusChange,
		Timestamp: time.Now().Unix(),
		NewStatus: cms.DCCStatusActive,
		Reason:    "new dcc",
	}
	scb, err := mdstream.EncodeDCCStatusChange(sc)
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
				ID:      mdstream.IDDCCGeneral,
				Payload: string(md),
			},
			{
				ID:      mdstream.IDDCCStatusChange,
				Payload: string(scb),
			},
		},
		Files: convertPDFilesFromWWW(files),
	}

	// Send the newrecord politeiad request
	responseBody, err := p.makeRequest(ctx, http.MethodPost,
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
	// An admin pubkey and signature are not included for
	// this reason.
	c := mdstream.RecordStatusChangeV2{
		Version:   mdstream.VersionRecordStatusChange,
		Timestamp: time.Now().Unix(),
		NewStatus: pd.RecordStatusPublic,
	}
	blob, err := mdstream.EncodeRecordStatusChangeV2(c)
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
				ID:      mdstream.IDRecordStatusChange,
				Payload: string(blob),
			},
		},
	}

	// Send SetUnvettedStatus request to politeiad
	responseBody, err = p.makeRequest(ctx, http.MethodPost,
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

	// Emit event notification for new DCC being submitted
	p.eventManager.emit(eventDCCNew,
		dataDCCNew{
			token: pdReply.CensorshipRecord.Token,
		})

	cr := convertWWWCensorFromPD(pdReply.CensorshipRecord)

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
	// All nominees, direct and subcontractors are allowed to be submitted
	// for an issuance.
	if (nomineeUser.ContractorType != cms.ContractorTypeNominee &&
		nomineeUser.ContractorType != cms.ContractorTypeDirect &&
		nomineeUser.ContractorType != cms.ContractorTypeSubContractor) &&
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

	// Check to see that if the issuance is for a subcontractor that the
	// sponsor user is a supervisor.
	if dcc.Type == cms.DCCTypeIssuance &&
		dcc.ContractorType == cms.ContractorTypeSubContractor &&
		sponsorUser.ContractorType != cms.ContractorTypeSupervisor {
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDCCContractorType,
		}

	}

	// Note that we need validate the string representation of the merkle
	files := convertPiFilesFromWWW([]www.File{nd.File})
	mr, err := wwwutil.MerkleRoot(files, nil)
	if err != nil {
		return err
	}
	if !pk.VerifyMessage([]byte(mr), sig) {
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

// getDCC gets the most recent verions of the given DCC from the cmsDB
// then fills in any missing user fields before returning the DCC record.
func (p *politeiawww) getDCC(token string) (*cms.DCCRecord, error) {
	// Get dcc from cmsdb
	r, err := p.cmsDB.DCCByToken(token)
	if err != nil {
		return nil, err
	}
	i := convertDCCDatabaseToRecord(r)

	// Check for possible malformed DCC
	if i.PublicKey == "" {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusMalformedDCC,
		}
	}

	// Get user IDs of support/oppose pubkeys
	supportUserIDs := make([]string, 0, len(i.SupportUserIDs))
	opposeUserIDs := make([]string, 0, len(i.OppositionUserIDs))
	supportUsernames := make([]string, 0, len(i.SupportUserIDs))
	opposeUsernames := make([]string, 0, len(i.OppositionUserIDs))
	for _, v := range i.SupportUserIDs {
		// Fill in userID and username fields
		u, err := p.db.UserGetByPubKey(v)
		if err != nil {
			log.Errorf("getDCC: getUserByPubKey: token:%v "+
				"pubKey:%v err:%v", token, v, err)
		} else {
			supportUserIDs = append(supportUserIDs, u.ID.String())
			supportUsernames = append(supportUsernames, u.Username)
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
			opposeUsernames = append(opposeUsernames, u.Username)
		}
	}
	i.SupportUserIDs = supportUserIDs
	i.OppositionUserIDs = opposeUserIDs
	i.SupportUsernames = supportUsernames
	i.OppositionUsernames = opposeUsernames

	// Fill in sponsoring userID and username fields
	u, err := p.db.UserGetByPubKey(i.PublicKey)
	if err != nil {
		log.Errorf("getDCC: getUserByPubKey: token:%v "+
			"pubKey:%v err:%v", token, i.PublicKey, err)
	} else {
		i.SponsorUserID = u.ID.String()
		i.SponsorUsername = u.Username
	}

	// Fill in nominee username

	nomineeUser, err := p.getCMSUserByID(i.DCC.NomineeUserID)
	if err != nil {
		log.Errorf("getDCC: getCMSUserByID: token:%v "+
			"userid:%v err:%v", token, i.DCC.NomineeUserID, err)
	} else {
		i.NomineeUsername = nomineeUser.Username
	}

	return &i, nil
}

func (p *politeiawww) processDCCDetails(ctx context.Context, gd cms.DCCDetails) (*cms.DCCDetailsReply, error) {
	log.Tracef("processDCCDetails: %v", gd.Token)
	vdr, err := p.cmsVoteDetails(ctx, gd.Token)
	if err != nil {
		return nil, err
	}

	vsr, err := p.cmsVoteSummary(ctx, gd.Token)
	if err != nil {
		return nil, err
	}

	dcc, err := p.getDCC(gd.Token)
	if err != nil {
		if errors.Is(err, cmsdatabase.ErrDCCNotFound) {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusDCCNotFound,
			}
			return nil, err
		}
	}

	voteResults := convertVoteOptionResultsToCMS(vsr.Results)

	voteSummary := cms.VoteSummary{
		UserWeights:    convertUserWeightToCMS(vdr.StartVote.UserWeights),
		EndHeight:      vsr.EndHeight,
		Results:        voteResults,
		Duration:       vsr.Duration,
		PassPercentage: vsr.PassPercentage,
	}
	reply := &cms.DCCDetailsReply{
		DCC:         *dcc,
		VoteSummary: voteSummary,
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
			log.Errorf("getDCCs: getDCC %v %v", v.Token, err)
			// Just skip to the next one but carry on with the rest.
			continue
		}
		dccs = append(dccs, *dcc)
	}

	return &cms.GetDCCsReply{
		DCCs: dccs,
	}, nil
}

func (p *politeiawww) processSupportOpposeDCC(ctx context.Context, sd cms.SupportOpposeDCC, u *user.User) (*cms.SupportOpposeDCCReply, error) {
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
		if errors.Is(err, cmsdatabase.ErrDCCNotFound) {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusDCCNotFound,
			}
			return nil, err
		}
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

	// Create the support/opposition record.
	c := mdstream.DCCSupportOpposition{
		Version:   mdstream.VersionDCCSupposeOpposition,
		PublicKey: sd.PublicKey,
		Timestamp: time.Now().Unix(),
		Vote:      sd.Vote,
		Signature: sd.Signature,
	}
	blob, err := mdstream.EncodeDCCSupportOpposition(c)
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
				ID:      mdstream.IDDCCSupportOpposition,
				Payload: string(blob),
			},
		},
	}

	responseBody, err := p.makeRequest(ctx, http.MethodPost,
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

	// Emit event notification for a DCC being supported/opposed
	p.eventManager.emit(eventDCCSupportOppose,
		dataDCCSupportOppose{
			token: sd.Token,
		})

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

func validateNewComment(c www.NewComment) error {
	// Validate token
	if !tokenIsValid(c.Token) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidCensorshipToken,
		}
	}
	// Validate max length
	if len(c.Comment) > www.PolicyMaxCommentLength {
		return www.UserError{
			ErrorCode: www.ErrorStatusCommentLengthExceededPolicy,
		}
	}
	return nil
}

// processNewCommentDCC sends a new comment decred plugin command to politeaid
// then fetches the new comment from the cache and returns it.
func (p *politeiawww) processNewCommentDCC(ctx context.Context, nc www.NewComment, u *user.User) (*www.NewCommentReply, error) {
	log.Tracef("processNewCommentDCC: %v %v", nc.Token, u.ID)

	// Validate comment
	err := validateNewComment(nc)
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
		if errors.Is(err, cmsdatabase.ErrDCCNotFound) {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusDCCNotFound,
			}
			return nil, err
		}
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
	responseBody, err := p.makeRequest(ctx, http.MethodPost,
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

	// Get comment
	comments, err := p.getDCCComments(ctx, nc.Token)
	if err != nil {
		return nil, fmt.Errorf("getComments: %v", err)
	}
	var c www.Comment
	for _, v := range comments {
		if v.CommentID == ncr.CommentID {
			c = v
			break
		}
	}

	return &www.NewCommentReply{
		Comment: c,
	}, nil
}

// processDCCComments returns all comments for a given dcc. If the user is
// logged in the user's last access time for the given comments will also be
// returned.
func (p *politeiawww) processDCCComments(ctx context.Context, token string, u *user.User) (*www.GetCommentsReply, error) {
	log.Tracef("processDCCComment: %v", token)

	// Fetch dcc comments from cache
	c, err := p.getDCCComments(ctx, token)
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

func (p *politeiawww) getDCCComments(ctx context.Context, token string) ([]www.Comment, error) {
	log.Tracef("getDCCComments: %v", token)

	dc, err := p.decredGetComments(ctx, token)
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

func (p *politeiawww) processSetDCCStatus(ctx context.Context, sds cms.SetDCCStatus, u *user.User) (*cms.SetDCCStatusReply, error) {
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
		if errors.Is(err, cmsdatabase.ErrDCCNotFound) {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusDCCNotFound,
			}
			return nil, err
		}
	}

	err = validateDCCStatusTransition(dcc.Status, sds.Status, sds.Reason)
	if err != nil {
		return nil, err
	}

	// Validate vote status
	vsr, err := p.cmsVoteSummary(ctx, sds.Token)
	if err != nil {
		return nil, err
	}

	// Only allow voting on All Vote DCC proposals
	// Get vote summary to check vote status
	bb, err := p.decredBestBlock(ctx)
	if err != nil {
		return nil, err
	}

	voteStatus := dccVoteStatusFromVoteSummary(*vsr, bb)
	switch voteStatus {
	case cms.DCCVoteStatusStarted:
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote has not finished"},
		}
	case cms.DCCVoteStatusInvalid:
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Create the change record.
	c := mdstream.DCCStatusChange{
		Version:        mdstream.VersionDCCStatusChange,
		AdminPublicKey: u.PublicKey(),
		Timestamp:      time.Now().Unix(),
		NewStatus:      sds.Status,
		Reason:         sds.Reason,
		Signature:      sds.Signature,
	}
	blob, err := mdstream.EncodeDCCStatusChange(c)
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
				ID:      mdstream.IDDCCStatusChange,
				Payload: string(blob),
			},
		},
	}

	responseBody, err := p.makeRequest(ctx, http.MethodPost,
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

	switch sds.Status {
	case cms.DCCStatusApproved:
		switch dcc.DCC.Type {
		case cms.DCCTypeIssuance:
			// Do DCC user Issuance processing
			err := p.issuanceDCCUser(dcc.DCC.NomineeUserID, dcc.SponsorUserID,
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

func (p *politeiawww) processCastVoteDCC(ctx context.Context, cv cms.CastVote, u *user.User) (*cms.CastVoteReply, error) {
	log.Tracef("processCastVoteDCC: %v", u.PublicKey())

	vdr, err := p.cmsVoteDetails(ctx, cv.Token)
	if err != nil {
		return nil, err
	}

	validVoteBit := false
	for _, option := range vdr.StartVote.Vote.Options {
		if cv.VoteBit == strconv.FormatUint(option.Bits, 16) {
			validVoteBit = true
			break
		}
	}

	if !validVoteBit {
		return nil, www.UserError{
			ErrorCode:    cms.ErrorStatusInvalidSupportOppose,
			ErrorContext: []string{"votebits not valid for given dcc vote"},
		}
	}

	// Only allow voting on All Vote DCC proposals
	// Get vote summary to check vote status

	bb, err := p.decredBestBlock(ctx)
	if err != nil {
		return nil, err
	}

	// Check to make sure that the Vote hasn't ended yet.
	if vdr.StartVoteReply.EndHeight < bb {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusDCCVoteEnded,
		}
	}

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	vote := convertCastVoteFromCMS(cv)
	payload, err := cmsplugin.EncodeCastVote(vote)
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        cmsplugin.ID,
		Command:   cmsplugin.CmdCastVote,
		CommandID: cmsplugin.CmdCastVote,
		Payload:   string(payload),
	}

	responseBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	// Decode plugin reply
	pluginCastVoteReply, err := cmsplugin.DecodeCastVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return convertCastVoteReplyToCMS(pluginCastVoteReply), nil
}

func (p *politeiawww) processVoteDetailsDCC(ctx context.Context, token string) (*cms.VoteDetailsReply, error) {
	log.Tracef("processVoteDetailsDCC: %v", token)

	// Validate vote status
	dvdr, err := p.cmsVoteDetails(ctx, token)
	if err != nil {
		if errors.Is(err, cmsdatabase.ErrDCCNotFound) {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusDCCNotFound,
			}
			return nil, err
		}
	}
	if dvdr.StartVoteReply.StartBlockHash == "" {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"voting has not started yet"},
		}
	}
	vdr, err := convertCMSStartVoteToCMSVoteDetailsReply(dvdr.StartVote,
		dvdr.StartVoteReply)
	if err != nil {
		return nil, err
	}

	return vdr, nil
}

// cmsVoteDetails sends the cms plugin votedetails command to the gitbe
// and returns the vote details for the passed in proposal.
func (p *politeiawww) cmsVoteDetails(ctx context.Context, token string) (*cmsplugin.VoteDetailsReply, error) {
	// Setup plugin command
	vd := cmsplugin.VoteDetails{
		Token: token,
	}
	payload, err := cmsplugin.EncodeVoteDetails(vd)
	if err != nil {
		return nil, err
	}
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        cmsplugin.ID,
		Command:   cmsplugin.CmdVoteDetails,
		Payload:   string(payload),
	}
	responseBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle reply
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
	vdr, err := cmsplugin.DecodeVoteDetailsReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return vdr, nil
}

// cmsVoteSummary provides the current tally of a given DCC proposal based on
// the provided token.
func (p *politeiawww) cmsVoteSummary(ctx context.Context, token string) (*cmsplugin.VoteSummaryReply, error) {
	// Setup plugin command
	vs := cmsplugin.VoteSummary{
		Token: token,
	}
	payload, err := cmsplugin.EncodeVoteSummary(vs)
	if err != nil {
		return nil, err
	}
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        cmsplugin.ID,
		Command:   cmsplugin.CmdVoteSummary,
		Payload:   string(payload),
	}
	responseBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle reply
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
	vsr, err := cmsplugin.DecodeVoteSummaryReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return vsr, nil
}

func (p *politeiawww) processActiveVoteDCC(ctx context.Context) (*cms.ActiveVoteReply, error) {
	log.Tracef("processActiveVoteDCC")

	// Request full record inventory from backend
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pdCommand := pd.Inventory{
		Challenge:    hex.EncodeToString(challenge),
		IncludeFiles: true,
		AllVersions:  true,
	}

	responseBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.InventoryRoute, pdCommand)
	if err != nil {
		return nil, err
	}

	var pdReply pd.InventoryReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal InventoryReply: %v",
			err)
	}

	// Verify the UpdateVettedMetadata challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}
	vetted := pdReply.Vetted

	bb, err := p.decredBestBlock(ctx)
	if err != nil {
		return nil, err
	}

	active := make([]string, 0, len(vetted))
	for _, r := range vetted {
		for _, m := range r.Metadata {
			switch m.ID {
			case mdstream.IDDCCGeneral:
				vs, err := p.cmsVoteSummary(ctx, r.CensorshipRecord.Token)
				if err != nil {
					log.Errorf("processActiveVotes: error pull cmsVoteSummary "+
						"%v %v", r.CensorshipRecord.Token, err)
					continue
				}
				if vs.EndHeight > bb {
					active = append(active, r.CensorshipRecord.Token)
				}
			}
		}
	}

	dccs, err := p.getDCCs(active)
	if err != nil {
		return nil, err
	}

	// Compile dcc vote tuples
	vt := make([]cms.VoteTuple, 0, len(dccs))
	for _, v := range dccs {
		// Get vote details from gitbe
		vdr, err := p.cmsVoteDetails(ctx, v.CensorshipRecord.Token)
		if err != nil {
			return nil, fmt.Errorf("decredVoteDetails %v: %v",
				v.CensorshipRecord.Token, err)
		}
		// Create vote tuple
		vt = append(vt, cms.VoteTuple{
			DCC:            v,
			StartVote:      convertCMSStartVoteToCMS(vdr.StartVote),
			StartVoteReply: convertCMSStartVoteReplyToCMS(vdr.StartVoteReply),
		})
	}

	return &cms.ActiveVoteReply{
		Votes: vt,
	}, nil
}

// getDCCs returns a [token]cms.DCCRecord map for the provided list of
// censorship tokens. If a proposal is not found, the map will not include an
// entry for the corresponding censorship token. It is the responsibility of
// the caller to ensure that results are returned for all of the provided
// censorship tokens.
func (p *politeiawww) getDCCs(tokens []string) (map[string]cms.DCCRecord, error) {
	log.Tracef("getDCCs: %v", tokens)

	// Use pointers for now so the props can be easily updated
	dccs := make(map[string]*cms.DCCRecord, len(tokens))
	for _, token := range tokens {
		dcc, err := p.getDCC(token)
		if err != nil {
			log.Errorf("getDCCs: unable to getDCC for %v %v", token, err)
		}
		dccs[token] = dcc
	}

	// Compile a list of unique proposal author pubkeys. These
	// are needed to lookup the proposal author info.
	pubKeys := make(map[string]struct{})
	for _, pr := range dccs {
		if _, ok := pubKeys[pr.PublicKey]; !ok {
			pubKeys[pr.PublicKey] = struct{}{}
		}
	}

	// Lookup proposal authors
	pk := make([]string, 0, len(pubKeys))
	for k := range pubKeys {
		pk = append(pk, k)
	}
	users, err := p.db.UsersGetByPubKey(pk)
	if err != nil {
		return nil, err
	}
	if len(users) != len(pubKeys) {
		// A user is missing from the userdb for one
		// or more public keys. We're in trouble!
		notFound := make([]string, 0, len(pubKeys))
		for v := range pubKeys {
			if _, ok := users[v]; !ok {
				notFound = append(notFound, v)
			}
		}
		e := fmt.Sprintf("users not found for pubkeys: %v",
			strings.Join(notFound, ", "))
		panic(e)
	}

	// Fill in proposal author info
	for i, pr := range dccs {
		dccs[i].SponsorUserID = users[pr.PublicKey].ID.String()
		dccs[i].SponsorUsername = users[pr.PublicKey].Username
	}

	// Convert pointers to values
	tDCCs := make(map[string]cms.DCCRecord, len(dccs))
	for token, dr := range dccs {
		tDCCs[token] = *dr
	}

	return tDCCs, nil
}

// processStartVoteV2 starts the voting period on a proposal using the provided
// v2 StartVote.
func (p *politeiawww) processStartVoteDCC(ctx context.Context, sv cms.StartVote, u *user.User) (*cms.StartVoteReply, error) {
	log.Tracef("processStartVoteDCC %v", sv.Vote.Token)

	// Sanity check
	if !u.Admin {
		return nil, fmt.Errorf("user is not an admin")
	}

	// Validate vote bits
	for _, v := range sv.Vote.Options {
		err := validateVoteBitDCC(sv.Vote, v.Bits)
		if err != nil {
			log.Debugf("processStartVoteDCC: invalid vote bits: %v", err)
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropVoteBits,
			}
		}
	}

	// Validate vote params
	switch {
	case sv.Vote.Duration < p.cfg.VoteDurationMin:
		e := fmt.Sprintf("vote duration must be > %v", p.cfg.VoteDurationMin)
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{e},
		}
	case sv.Vote.Duration > p.cfg.VoteDurationMax:
		e := fmt.Sprintf("vote duration must be < %v", p.cfg.VoteDurationMax)
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{e},
		}
	case sv.Vote.QuorumPercentage > 100:
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{"quorum percentage must be <= 100"},
		}
	case sv.Vote.PassPercentage > 100:
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{"pass percentage must be <= 100"},
		}
	}

	// Ensure the public key is the user's active key
	if sv.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	dsv := convertStartVoteToCMS(sv)

	userWeights, err := p.getCMSUserWeights()
	if err != nil {
		return nil, err
	}

	cmsUserWeights := make([]cmsplugin.UserWeight, 0, len(userWeights))
	for id, weight := range userWeights {
		cmsuw := cmsplugin.UserWeight{
			UserID: id,
			Weight: weight,
		}
		cmsUserWeights = append(cmsUserWeights, cmsuw)
	}
	dsv.UserWeights = cmsUserWeights

	err = dsv.VerifySignature()
	if err != nil {
		log.Debugf("processStartVote: VerifySignature: %v", err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Validate proposal version and status
	pr, err := p.getDCC(sv.Vote.Token)
	if err != nil {
		if errors.Is(err, cmsdatabase.ErrDCCNotFound) {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
			return nil, err
		}
	}
	if pr.Status != cms.DCCStatusActive {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongStatus,
			ErrorContext: []string{"dcc is not active"},
		}
	}

	// Validate vote status
	vsr, err := p.cmsVoteSummary(ctx, sv.Vote.Token)
	if err != nil {
		return nil, err
	}

	// Only allow voting on All Vote DCC proposals
	// Get vote summary to check vote status

	bb, err := p.decredBestBlock(ctx)
	if err != nil {
		return nil, err
	}

	voteStatus := dccVoteStatusFromVoteSummary(*vsr, bb)
	switch voteStatus {
	case cms.DCCVoteStatusStarted:
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote already started"},
		}
	case cms.DCCVoteStatusFinished:
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote already finished"},
		}
	case cms.DCCVoteStatusInvalid:
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Tell decred plugin to start voting
	payload, err := cmsplugin.EncodeStartVote(dsv)
	if err != nil {
		return nil, err
	}
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        cmsplugin.ID,
		Command:   cmsplugin.CmdStartVote,
		CommandID: cmsplugin.CmdStartVote + " " + sv.Vote.Token,
		Payload:   string(payload),
	}
	responseBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle reply
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
	dsvr, err := cmsplugin.DecodeStartVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	svr := convertCMSStartVoteReplyToCMS(dsvr)
	if err != nil {
		return nil, err
	}

	/// XXX Do some sort of notification?

	return &svr, nil
}

// validateVoteBitDCC ensures that bit is a valid vote bit.
func validateVoteBitDCC(vote cms.Vote, bit uint64) error {
	if len(vote.Options) == 0 {
		return fmt.Errorf("vote corrupt")
	}
	if bit == 0 {
		return fmt.Errorf("invalid bit 0x%x", bit)
	}
	if vote.Mask&bit != bit {
		return fmt.Errorf("invalid mask 0x%x bit 0x%x",
			vote.Mask, bit)
	}

	for _, v := range vote.Options {
		if v.Bits == bit {
			return nil
		}
	}

	return fmt.Errorf("bit not found 0x%x", bit)
}

func dccVoteStatusFromVoteSummary(r cmsplugin.VoteSummaryReply, bestBlock uint32) cms.DCCVoteStatusT {
	switch {
	case r.EndHeight == 0:
		return cms.DCCVoteStatusNotStarted
	default:
		if bestBlock < r.EndHeight {
			return cms.DCCVoteStatusStarted
		}

		return cms.DCCVoteStatusFinished
	}
}
