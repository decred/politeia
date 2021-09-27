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
)

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
		Token:     av.Token, // This token will be changed with the new tlog one
		Version:   uint32(av.Version),
		Action:    av.Action,
		PublicKey: av.PublicKey,
		Signature: av.Signature,
	}, nil
}

// convertStartVoteMetadata converts the 14.metadata.txt file to the start
// details structure from tlog backend. This is used further to populate some
// fields of vote details before saving its blob to the tstore.
func convertStartVoteMetadata(path string) (*tv.Start, error) {
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
					Parent:           "", // Will be set later on
				},
				PublicKey: av.PublicKey,
				Signature: av.Signature,
			},
		},
	}, nil
}

// convertVoteDetailsMetadata converts the 15.metadata.txt file to the vote
// details structure from tlog backend.
func convertVoteDetailsMetadata(path string, startDetails []tv.StartDetails) (*tv.VoteDetails, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vd voteDetailsV1
	err = json.Unmarshal(b, &vd)
	if err != nil {
		return nil, err
	}

	// Parse block height
	sbh, err := strconv.Atoi(vd.StartBlockHeight)
	if err != nil {
		return nil, err
	}

	ebh, err := strconv.Atoi(vd.EndHeight)
	if err != nil {
		return nil, err
	}

	return &tv.VoteDetails{
		Params:    startDetails[0].Params,
		PublicKey: startDetails[0].PublicKey,
		Signature: startDetails[0].Signature,

		StartBlockHeight: uint32(sbh),
		StartBlockHash:   vd.StartBlockHash,
		EndBlockHeight:   uint32(ebh),
		EligibleTickets:  vd.EligibleTickets,
	}, nil
}

// convertBallotJournal walks the ballot journal, parsing the entries data and
// saving their respective blob on tstore.
func (l *legacyImport) convertBallotJournal(path string, newToken []byte) error {
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		return err
	}

	s := bufio.NewScanner(fh)

	fmt.Printf("  ticketvote: Parsing ballot journal for %v ...\n", hex.EncodeToString(newToken))

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
				return fmt.Errorf("ballot journal add: %v", err)
			}

			cv := tv.CastVoteDetails{
				Token:     hex.EncodeToString(newToken),
				Ticket:    cvj.CastVote.Ticket,
				VoteBit:   cvj.CastVote.VoteBit,
				Signature: cvj.CastVote.Signature,
				Receipt:   cvj.Receipt,
			}

			err = l.blobSaveCastVoteDetails(cv, newToken)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid ballot journal action")
		}
	}

	fmt.Printf("  ticketvote: Done for %v!\n", hex.EncodeToString(newToken))

	return nil
}

func (l *legacyImport) blobSaveCastVoteDetails(castVoteDetails tv.CastVoteDetails, newToken []byte) error {
	data, err := json.Marshal(castVoteDetails)
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
	if err != nil && err.Error() == "duplicate blob" {
		return nil
	}
	if err != nil {
		return err
	}

	return nil
}

func (l *legacyImport) blobSaveAuthDetails(authDetails tv.AuthDetails, newToken []byte) error {
	// Set new tlog token to auth details.
	authDetails.Token = hex.EncodeToString(newToken)

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
	// Set new tlog token to vote details params.
	voteDetails.Params.Token = hex.EncodeToString(newToken)

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
