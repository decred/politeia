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
					Parent:           "", //TODO: properly populate for runoff votes
				},
				PublicKey: av.PublicKey,
				Signature: av.Signature,
			},
		},
	}, nil
}

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

	// Assume this is a standard vote.
	// TODO: add conditions for rfp props and runoff votes.
	sd := startDetails[0]

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
		Params:    sd.Params,
		PublicKey: sd.PublicKey,
		Signature: sd.Signature,

		StartBlockHeight: uint32(sbh),
		StartBlockHash:   vd.StartBlockHash,
		EndBlockHeight:   uint32(ebh),
		EligibleTickets:  vd.EligibleTickets,
	}, nil
}

func (l *legacyImport) convertBallotJournal(path string, newToken []byte) error {
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		return err
	}

	s := bufio.NewScanner(fh)

	fmt.Println("about to read ballot journal")
	for i := 0; s.Scan(); i++ {
		// json text from reading each journal line
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

				Receipt: cvj.Receipt,
				// Server generated metadata being left blank:
				//   - Address
				//   - Timestamps
			}

			err = l.blobSaveCastVoteDetails(cv, newToken)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid ballot journal action")
		}

		// fmt.Println(s.Text())
	}
	fmt.Println("done reading ballot journal")

	return nil
}

func (l *legacyImport) blobSaveCastVoteDetails(castVoteDetails tv.CastVoteDetails, newToken []byte) error {
	// fmt.Println(" ticketvote: Saving CastVoteDetails blob ...")

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
	if err != nil {
		return err
	}

	// fmt.Println(" ticketvote: Saved!")

	return nil
}

func (l *legacyImport) blobSaveAuthDetails(authDetails tv.AuthDetails, newToken []byte) error {
	fmt.Println(" ticketvote: Saving AuthDetails blob ...")

	// Update metadata with new token instead of legacy one.
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

	fmt.Println(" ticketvote: Saved!")

	return nil
}

func (l *legacyImport) blobSaveVoteDetails(voteDetails tv.VoteDetails, newToken []byte) error {
	fmt.Println(" ticketvote: Saving VoteDetails blob ...")

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

	fmt.Println(" ticketvote: Saved!")

	return nil
}
