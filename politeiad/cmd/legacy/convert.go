package main

import (
	"encoding/json"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/decred/politeia/mdstream"
	backendv1 "github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backendv2"
	backend "github.com/decred/politeia/politeiad/backendv2"
	tv "github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	pusermd "github.com/decred/politeia/politeiad/plugins/usermd"
	v1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
)

// convertRecordMetadata reads the recordmetadata.json from the gitbe record
// and converts it to a RecordMetadata tstorebe struct.
func convertRecordMetadata(path string) (*backendv2.RecordMetadata, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var mdv1 *backendv1.RecordMetadata
	err = json.Unmarshal(b, &mdv1)
	if err != nil {
		return nil, err
	}

	var mdv2 backendv2.RecordMetadata
	mdv2.Token = mdv1.Token
	mdv2.State = backend.StateVetted
	mdv2.Merkle = mdv1.Merkle
	mdv2.Timestamp = mdv1.Timestamp
	mdv2.Version = 1
	mdv2.Iteration = 1

	// Convert backend v1 status to v2.
	switch {
	case mdv1.Status == backendv1.MDStatusInvalid:
		mdv2.Status = backendv2.StatusInvalid
	case mdv1.Status == backendv1.MDStatusUnvetted:
		mdv2.Status = backendv2.StatusUnreviewed
	case mdv1.Status == backendv1.MDStatusVetted:
		mdv2.Status = backendv2.StatusPublic
	case mdv1.Status == backendv1.MDStatusCensored:
		mdv2.Status = backendv2.StatusCensored
	case mdv1.Status == backendv1.MDStatusIterationUnvetted:
		mdv2.Status = backendv2.StatusUnreviewed
	case mdv1.Status == backendv1.MDStatusArchived:
		mdv2.Status = backendv2.StatusArchived
	default:
		return nil, err
	}

	return &mdv2, nil
}

// convertStatusChangeMetadata converts the 02.metadata.txt status change md
// from legacy git records.
func convertStatusChangeMetadata(path string) (*usermd.StatusChangeMetadata, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var (
		rsc     mdstream.RecordStatusChangeV2
		streams []mdstream.RecordStatusChangeV2
	)
	err = json.Unmarshal(b, &rsc)
	if err != nil {
		// Record has 02.metadata.txt containing nested status changes.
		split := strings.Split(string(b), "}")
		for _, v := range split {
			if v == "" {
				continue
			}
			err = json.Unmarshal([]byte(v+"}"), &rsc)
			if err != nil {
				return nil, err
			}
			streams = append(streams, rsc)
		}
	} else {
		streams = append(streams, rsc)
	}

	// Return most recent status change md.
	latest := streams[len(streams)-1]

	// Many proposals do not have the signature on the 02.metadata.txt
	// status change data.
	return &pusermd.StatusChangeMetadata{
		Version:   uint32(latest.Version),
		Status:    uint32(latest.NewStatus),
		Reason:    latest.StatusChangeMessage,
		PublicKey: latest.AdminPubKey,
		Signature: latest.Signature,
		Timestamp: latest.Timestamp,
	}, nil
}

// convertUserMetadata converts the 00.metadata.txt file which contains the
// ProposalGeneralV1 metadata structure previously used on legacy git records.
func (l *legacy) convertUserMetadata(path string) (*usermd.UserMetadata, string, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	var pgv1 proposalGeneralV1
	err = json.Unmarshal(b, &pgv1)
	if err != nil {
		return nil, "", err
	}

	usr, err := l.fetchUserByPubKey(pgv1.PublicKey)
	if err != nil {
		return nil, "", err
	}

	// Check if test mode is set and adjust.
	userID := usr.ID
	if *cmdDumpTest {
		userID = cmdDumpUserID
	}

	// If userid/publickey is data from a user that is not registered in the
	// local userdb this tool is using, then recordSave will error out.
	return &pusermd.UserMetadata{
		UserID:    userID,
		PublicKey: pgv1.PublicKey,

		// The signature for this struct is not coherent on tlog due to
		// significant data changes.

		// Signature: pgv1.Signature,
	}, pgv1.Name, nil
}

// Conversion methods

// convertAuthDetailsMetadata converts the 13.metadata.txt file to the
// auth details structure from tlog backend.
func convertAuthDetailsMetadata(path string) (*tv.AuthDetails, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var av authorizeVoteV1
	err = json.Unmarshal(b, &av)
	if err != nil {
		return nil, err
	}

	return &tv.AuthDetails{
		Token:     av.Token,
		Version:   uint32(av.Version),
		Action:    av.Action,
		PublicKey: av.PublicKey,
		Signature: av.Signature,
		Timestamp: av.Timestamp,
		Receipt:   av.Receipt,
	}, nil
}

// convertStartVoteMetadata converts the 14.metadata.txt file to the start
// details struct from tstore backend. This is used further to populate data
// of the vote details blob.
func (l *legacy) convertStartVoteMetadata(path string) (*tv.Start, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var av startVoteV1
	err = json.Unmarshal(b, &av)
	if err != nil {
		return nil, err
	}

	var opts []tv.VoteOption
	for _, v := range av.Vote.Options {
		opts = append(opts, tv.VoteOption{
			ID:          v.Id,
			Description: v.Description,
			Bit:         v.Bits,
		})
	}

	// Some 14.metadata.txt files before RFP feature do not contain the vote
	// type information. Define it manually here.
	if av.Vote.Type == 0 {
		av.Vote.Type = int(tv.VoteTypeStandard)
	}

	return &tv.Start{
		Starts: []tv.StartDetails{
			{
				Params: tv.VoteParams{
					Token:            av.Vote.Token,
					Version:          uint32(av.Version),
					Type:             tv.VoteT(av.Vote.Type),
					Mask:             av.Vote.Mask,
					Duration:         av.Vote.Duration,
					QuorumPercentage: av.Vote.QuorumPercentage,
					PassPercentage:   av.Vote.PassPercentage,
					Options:          opts,
				},
				PublicKey: av.PublicKey,

				// The signature for this struct is not sound on tlog due to
				// significant data changes.

				// Signature: av.Signature,
			},
		},
	}, nil
}

// convertVoteDetailsMetadata converts the 15.metadata.txt file to the vote
// details structure from tlog backend. It also uses part of the 14.metadata.txt
// data, the StartDetails struct, to feed the Params data for the vote details.
func convertVoteDetailsMetadata(path string, startDetails tv.StartDetails) (*tv.VoteDetails, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vd voteDetailsV1
	err = json.Unmarshal(b, &vd)
	if err != nil {
		return nil, err
	}

	// Parse start height and end height.
	sbh, err := strconv.Atoi(vd.StartBlockHeight)
	if err != nil {
		return nil, err
	}
	ebh, err := strconv.Atoi(vd.EndHeight)
	if err != nil {
		return nil, err
	}

	return &tv.VoteDetails{
		Params:    startDetails.Params,
		PublicKey: startDetails.PublicKey,

		StartBlockHeight: uint32(sbh),
		StartBlockHash:   vd.StartBlockHash,
		EndBlockHeight:   uint32(ebh),
		EligibleTickets:  vd.EligibleTickets,

		// The signature for this struct is not coherent on tlog due to
		// significant data changes.
	}, nil
}

// convertAuthDetailsToV1 is used to verify the auth details signature
// through the www client.
func convertAuthDetailsToV1(auth tv.AuthDetails) v1.AuthDetails {
	return v1.AuthDetails{
		Token:     auth.Token,
		Version:   auth.Version,
		Action:    auth.Action,
		PublicKey: auth.PublicKey,
		Signature: auth.Signature,
		Timestamp: auth.Timestamp,
		Receipt:   auth.Receipt,
	}
}

// convertCastVoteDetailsToV1 is used to verify the cast vote details signature
// through the www client.
func convertCastVoteDetailsToV1(vote tv.CastVoteDetails) v1.CastVoteDetails {
	return v1.CastVoteDetails{
		Token:     vote.Token,
		Ticket:    vote.Ticket,
		VoteBit:   vote.VoteBit,
		Address:   vote.Address,
		Signature: vote.Signature,
		Receipt:   vote.Receipt,
		Timestamp: vote.Timestamp,
	}
}
