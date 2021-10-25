package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/decred/politeia/politeiad/backend/gitbe"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	tv "github.com/decred/politeia/politeiad/plugins/ticketvote"
	v1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/client"
)

// parseBallotJournal walks through the legacy ballot journal converting
// the payloads to their tstore blob equivalents.
func (l *legacyImport) parseBallotJournal(path, legacyToken string, newToken []byte) error {
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		return err
	}

	// First pre parse the ballot journal and build the tickets slice and
	// cast vote details slice. These are used to fetch the largest commitment
	// address and to save the vote blobs onto tstore.
	var (
		tickets         []string // Used to fetch largest commitment address
		castVoteDetails []*tv.CastVoteDetails
	)
	s := bufio.NewScanner(fh)
	for i := 0; s.Scan(); i++ {
		ss := bytes.NewReader([]byte(s.Text()))
		d := json.NewDecoder(ss)
		var action gitbe.JournalAction
		err := d.Decode(&action)
		if err != nil {
			return err
		}

		switch action.Action {
		case "add":
			var cvj castVoteJournalV1
			err = d.Decode(&cvj)
			if err != nil {
				return err
			}

			tickets = append(tickets, cvj.CastVote.Ticket)
			castVoteDetails = append(castVoteDetails, &tv.CastVoteDetails{
				Token:     cvj.CastVote.Token,
				Ticket:    cvj.CastVote.Ticket,
				VoteBit:   cvj.CastVote.VoteBit,
				Signature: cvj.CastVote.Signature,
				Receipt:   cvj.Receipt,
				// Add git timestamp.
			})

		default:
			return fmt.Errorf("invalid ballot journal action")
		}
	}

	addrs, err := largestCommitmentAddresses(tickets)
	if err != nil {
		panic(err)
	}

	fmt.Printf("  ticketvote: %v parsing ballot journal...\n", legacyToken[:7])

	// Save the cast vote details blob into tstore, and its respective vote
	// collider blob. This will also limit the number of votes saved to store
	// if the ballotCount flag is set.
	var count int
	for _, details := range castVoteDetails {
		cv := details
		cv.Address = addrs[cv.Ticket].bestAddr

		// Save cast vote details to tstore.
		err = l.blobSaveCastVoteDetails(*cv, newToken)
		if err != nil {
			return err
		}

		// Save vote collider blob to tstore.
		vc := voteCollider{
			Token:  hex.EncodeToString(newToken),
			Ticket: cv.Ticket,
		}
		err = l.blobSaveVoteCollider(vc, newToken)
		if err != nil {
			return err
		}

		// Limit votes if ballot count flag is set.
		if *ballotCount != 0 {
			count++
			if count == *ballotCount {
				break
			}
		}
	}

	fmt.Printf("  ticketvote: %v Done!\n", legacyToken[:7])

	return nil
}

func (l *legacyImport) blobSaveCastVoteDetails(cdv tv.CastVoteDetails, newToken []byte) error {
	// Verify cast vote details signature.
	err := client.CastVoteDetailsVerify(convertCastVoteDetailsToV1(cdv), serverPubkey)
	if err != nil {
		return err
	}

	data, err := json.Marshal(cdv)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: tv.PluginID + "-castvote-v1",
		})
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, data)

	err = l.tstore.BlobSave(newToken, be)
	if err != nil && err.Error() == "duplicate payload" {
		return nil
	}
	if err != nil {
		return err
	}

	return nil
}

func (l *legacyImport) blobSaveAuthDetails(authDetails tv.AuthDetails, newToken []byte) error {
	// Verify auth details signature.
	err := client.AuthDetailsVerify(convertAuthDetailsToV1(authDetails),
		serverPubkey)
	if err != nil {
		return err
	}

	data, err := json.Marshal(authDetails)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: tv.PluginID + "-auth-v1",
		})
	if err != nil {
		return err
	}

	be := store.NewBlobEntry(hint, data)
	err = l.tstore.BlobSave(newToken, be)
	if err != nil {
		return err
	}

	return nil
}

func (l *legacyImport) blobSaveVoteDetails(voteDetails tv.VoteDetails, newToken []byte) error {
	data, err := json.Marshal(voteDetails)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: tv.PluginID + "-vote-v1",
		})
	if err != nil {
		return err
	}

	be := store.NewBlobEntry(hint, data)
	err = l.tstore.BlobSave(newToken, be)
	if err != nil {
		return err
	}

	return nil
}

func (l *legacyImport) blobSaveVoteCollider(vc voteCollider, newToken []byte) error {
	data, err := json.Marshal(vc)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: tv.PluginID + "-vcollider-v1",
		})
	if err != nil {
		return err
	}

	be := store.NewBlobEntry(hint, data)
	err = l.tstore.BlobSave(newToken, be)
	if err != nil {
		return err
	}

	return nil
}

func (l *legacyImport) blobSaveStartRunoff(srr startRunoffRecord, newToken []byte) error {
	data, err := json.Marshal(srr)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: tv.PluginID + "-startrunoff-v1",
		})
	if err != nil {
		return err
	}

	be := store.NewBlobEntry(hint, data)
	err = l.tstore.BlobSave(newToken, be)
	if err != nil {
		return err
	}

	return nil
}

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
func (l *legacyImport) convertStartVoteMetadata(path string) (*tv.Start, error) {
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

		// Signature: startDetails.Signature,
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
