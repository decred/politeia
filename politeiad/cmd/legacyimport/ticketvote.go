package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	dcrdata "github.com/decred/dcrdata/v6/api/types"
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
					Parent:           "", // This is set at the end of parsing.
				},
				PublicKey: av.PublicKey,
				Signature: av.Signature,
			},
		},
	}, nil
}

// convertVoteDetailsMetadata converts the 15.metadata.txt file to the vote
// details structure from tlog backend.
// TODO: review. see how its done on ticketvote/cmds.go. how vote details is saved for RFP subs
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
func (l *legacyImport) convertBallotJournal(path, legacyToken string, newToken []byte) error {
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		return err
	}

	fmt.Printf("  ticketvote: Pre parsing ballot journal for %v...\n", legacyToken)

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
				return fmt.Errorf("ballot journal add: %v", err)
			}

			tickets = append(tickets, cvj.CastVote.Ticket)
			castVoteDetails = append(castVoteDetails, &tv.CastVoteDetails{
				Token:     hex.EncodeToString(newToken),
				Ticket:    cvj.CastVote.Ticket,
				VoteBit:   cvj.CastVote.VoteBit,
				Signature: cvj.CastVote.Signature,
				Receipt:   cvj.Receipt,
				// Add commitment address
				// Add timestamp
			})

		default:
			return fmt.Errorf("invalid ballot journal action")
		}
	}

	fmt.Println("  ticketvote: Fetching largest commitment addresses from dcrdata...")

	lcr, err := largestCommitmentAddresses(tickets)
	if err != nil {
		panic(err)
	}

	fmt.Printf("  ticketvote: Saving ticketvote blobs to tstore for %v...\n", legacyToken)

	for k := range castVoteDetails {
		// Save cast vote details blob to tstore.
		cv := castVoteDetails[k]     // vote details
		cv.Address = lcr[k].bestAddr // largest commitment address
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
	}

	fmt.Printf("  ticketvote: Done for %v!\n", legacyToken)

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

// Get largest commitment address from dcrdata
func batchTransactions(hashes []string) ([]dcrdata.TrimmedTx, error) {
	// Request body is dcrdataapi.Txns marshalled to JSON
	reqBody, err := json.Marshal(dcrdata.Txns{
		Transactions: hashes,
	})
	if err != nil {
		return nil, err
	}

	// Make the POST request
	url := "https://dcrdata.decred.org/api/txs/trimmed"
	r, err := http.Post(url, "application/json; charset=utf-8",
		bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("dcrdata error: %v %v %v",
				r.StatusCode, url, err)
		}
		return nil, fmt.Errorf("dcrdata error: %v %v %s",
			r.StatusCode, url, body)
	}

	// Unmarshal the response
	var ttx []dcrdata.TrimmedTx
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ttx); err != nil {
		return nil, err
	}
	return ttx, nil
}

// largestCommitmentResult returns the largest commitment address or an error.
type largestCommitmentResult struct {
	bestAddr string
	err      error
}

func largestCommitmentAddresses(hashes []string) ([]largestCommitmentResult, error) {
	// Batch request all of the transaction info from dcrdata.
	ttxs, err := batchTransactions(hashes)
	if err != nil {
		return nil, err
	}

	// Find largest commitment address for each transaction.
	r := make([]largestCommitmentResult, len(hashes))
	for i := range ttxs {
		// Best is address with largest commit amount.
		var bestAddr string
		var bestAmount float64
		for _, v := range ttxs[i].Vout {
			if v.ScriptPubKeyDecoded.CommitAmt == nil {
				continue
			}
			if *v.ScriptPubKeyDecoded.CommitAmt > bestAmount {
				if len(v.ScriptPubKeyDecoded.Addresses) == 0 {
					// jrick, does this need to be printed?
					fmt.Errorf("unexpected addresses "+
						"length: %v", ttxs[i].TxID)
					continue
				}
				bestAddr = v.ScriptPubKeyDecoded.Addresses[0]
				bestAmount = *v.ScriptPubKeyDecoded.CommitAmt
			}
		}

		if bestAddr == "" || bestAmount == 0.0 {
			r[i].err = fmt.Errorf("no best commitment address found: %v",
				ttxs[i].TxID)
			continue
		}
		r[i].bestAddr = bestAddr
	}

	return r, nil
}
