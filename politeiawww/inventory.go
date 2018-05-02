package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/davecgh/go-spew/spew"

	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

var (
	errRecordNotFound = fmt.Errorf("record not found")
)

type inventoryRecord struct {
	record     pd.Record               // actual record
	proposalMD BackendProposalMetadata // proposal metadata
	comments   map[string]www.Comment  // [id]comment
	changes    []MDStreamChanges       // changes metadata
	votebits   www.Vote                // vote bits and options
	voting     www.StartVoteReply      // voting metadata
}

// proposalsRequest is used for passing parameters into the
// getProposals() function.
type proposalsRequest struct {
	After     string
	Before    string
	UserId    string
	StatusMap map[www.PropStatusT]bool
}

// updateInventoryRecord updates an existing record.
//
// This function must be called WITH the mutex held.
func (b *backend) updateInventoryRecord(record pd.Record) {
	b.inventory[record.CensorshipRecord.Token] = &inventoryRecord{
		record:   record,
		comments: make(map[string]www.Comment),
	}
}

// newInventoryRecord adds a record to the inventory.
//
// This function must be called WITH the mutex held.
func (b *backend) newInventoryRecord(record pd.Record) error {
	t := record.CensorshipRecord.Token
	if _, ok := b.inventory[t]; ok {
		return fmt.Errorf("duplicate token: %v", t)
	}

	b.updateInventoryRecord(record)

	return nil
}

// loadPropMD decodes backend proposal metadata and stores it inventory object.
//
// This function must be called WITH the mutex held.
func (b *backend) loadPropMD(token, payload string) error {
	f := strings.NewReader(payload)
	d := json.NewDecoder(f)
	var md BackendProposalMetadata
	if err := d.Decode(&md); err == io.EOF {
		b.inventory[token].proposalMD = md
	} else if err != nil {
		return err
	}
	return nil
}

// loadChanges decodes chnages metadata and stores it inventory object.
//
// This function must be called WITH the mutex held.
func (b *backend) loadChanges(token, payload string) error {
	f := strings.NewReader(payload)
	d := json.NewDecoder(f)
	for {
		var md MDStreamChanges
		if err := d.Decode(&md); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		p := b.inventory[token]
		p.changes = append(p.changes, md)
	}
}

// loadVoting decodes voting metadata and stores it inventory object.
//
// This function must be called WITH the mutex held.
func (b *backend) loadVoting(token, payload string) error {
	//f := strings.NewReader(payload)
	//d := json.NewDecoder(f)
	//var md decredplugin.StartVoteReply
	//if err := d.Decode(&md); err == io.EOF {
	//	return nil
	//} else if err != nil {
	//	return err
	//}
	//p := b.inventory[token]
	//p.voting = md
	panic("loadVoting")
	return nil
}

// loadVoteBits decodes voting metadata and stores it inventory object.
//
// This function must be called WITH the mutex held.
func (b *backend) loadVoteBits(token, payload string) error {
	//f := strings.NewReader(payload)
	//d := json.NewDecoder(f)
	//var md decredplugin.Vote
	//if err := d.Decode(&md); err == io.EOF {
	//	return nil
	//} else if err != nil {
	//	return err
	//}
	//p := b.inventory[token]
	//p.votebits = md
	panic("loadVoteBits")
	return nil
}

// loadComments calls out to the decred plugin to obtain all comments.
//
// This function must be called WITH the mutex held.
// XXX this call should be converted to run without the mutext held!
func (b *backend) loadComments(t string) error {
	// Load comments journal
	log.Tracef("loadComments: %v", t)

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return err
	}

	payload, err := decredplugin.EncodeGetComments(decredplugin.GetComments{
		Token: t,
	})
	if err != nil {
		return err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdGetComments,
		CommandID: decredplugin.CmdGetComments,
		Payload:   string(payload),
	}

	responseBody, err := b.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return err
	}

	// Decode plugin reply
	gcr, err := decredplugin.DecodeGetCommentsReply([]byte(reply.Payload))
	if err != nil {
		return err
	}

	// Fill map
	for _, v := range gcr.Comments {
		c := b.convertDecredCommentToWWWComment(v)
		b.inventory[t].comments[v.CommentID] = c
	}

	log.Tracef("loadComments: %v inserted %v", t, len(gcr.Comments))

	return nil
}

// loadReocrd load an entire record into inventory.
//
// This function must be called WITH the mutex held.
func (b *backend) loadRecord(v pd.Record) {
	t := v.CensorshipRecord.Token

	// Fish metadata out as well
	var err error
	for _, m := range v.Metadata {
		switch m.ID {
		case mdStreamGeneral:
			err = b.loadPropMD(t, m.Payload)
			if err != nil {
				log.Errorf("initializeInventory "+
					"could not load metadata: %v",
					err)
				continue
			}
		case mdStreamChanges:
			err = b.loadChanges(t, m.Payload)
			if err != nil {
				log.Errorf("initializeInventory "+
					"could not load changes: %v",
					err)
				continue
			}
		case decredplugin.MDStreamVotes:
			// This is all handled in the plugin bits.
			log.Debugf("initializeInventory skipping MDStreamVotes")
			continue
		case decredplugin.MDStreamVoteBits:
			err = b.loadVoteBits(t, m.Payload)
			if err != nil {
				log.Errorf("initializeInventory "+
					"could not load vote bits: %v", err)
				continue
			}
		case decredplugin.MDStreamVoteSnapshot:
			err = b.loadVoting(t, m.Payload)
			if err != nil {
				log.Errorf("initializeInventory "+
					"could not load vote snapshot: %v", err)
				continue
			}
		default:
			// log error but proceed
			log.Errorf("initializeInventory: invalid "+
				"metadata stream ID %v token %v",
				m.ID, t)
		}
	}

	// This is not normal metadata since we always need the journal
	err = b.loadComments(t)
	if err != nil {
		log.Errorf("could not load comments: %v", err)
	}
}

// initializeInventory initializes the inventory map and loads it with a
// InventoryReply.
//
// This function must be called WITH the mutex held.
func (b *backend) initializeInventory(inv *pd.InventoryReply) error {
	b.inventory = make(map[string]*inventoryRecord)

	for _, v := range append(inv.Vetted, inv.Branches...) {
		err := b.newInventoryRecord(v)
		if err != nil {
			return err
		}
		b.loadRecord(v)
	}

	return nil
}

// _getInventoryRecord reads an inventory record from the inventory cache.
//
// This function must be called WITH the mutex held.
func (b *backend) _getInventoryRecord(token string) (inventoryRecord, error) {
	r, ok := b.inventory[token]
	if !ok {
		return inventoryRecord{}, errRecordNotFound
	}
	return *r, nil
}

// getInventoryRecord returns an inventory record from the inventory cache.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) getInventoryRecord(token string) (inventoryRecord, error) {
	b.RLock()
	defer b.RUnlock()
	return b._getInventoryRecord(token)
}

// getProposal returns a single proposal by its token
func (b *backend) getProposal(token string) (www.ProposalRecord, error) {
	ir, err := b._getInventoryRecord(token)
	if err != nil {
		return www.ProposalRecord{}, err
	}
	pr := convertPropFromInventoryRecord(&ir, b.userPubkeys)
	return pr, nil
}

// getProposals returns a list of proposals that adheres to the requirements
// specified in the provided request.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) getProposals(pr proposalsRequest) []www.ProposalRecord {
	b.RLock()

	allProposals := make([]www.ProposalRecord, 0, len(b.inventory))
	for _, vv := range b.inventory {
		v := convertPropFromInventoryRecord(vv, b.userPubkeys)

		// Set the number of comments.
		v.NumComments = uint(len(vv.comments))

		// Look up and set the user id and username.
		var ok bool
		v.UserId, ok = b.userPubkeys[v.PublicKey]
		if ok {
			v.Username = b.getUsernameById(v.UserId)
		} else {
			log.Infof("%v", spew.Sdump(b.userPubkeys))
			log.Errorf("user not found for public key %v, for proposal %v",
				v.PublicKey, v.CensorshipRecord.Token)
		}

		len := len(allProposals)
		if len == 0 {
			allProposals = append(allProposals, v)
			continue
		}

		// Insertion sort from oldest to newest.
		idx := sort.Search(len, func(i int) bool {
			return v.Timestamp < allProposals[i].Timestamp
		})

		allProposals = append(allProposals[:idx],
			append([]www.ProposalRecord{v},
				allProposals[idx:]...)...)
	}

	b.RUnlock()

	// pageStarted stores whether or not it's okay to start adding
	// proposals to the array. If the after or before parameter is
	// supplied, we must find the beginning (or end) of the page first.
	pageStarted := (pr.After == "" && pr.Before == "")
	beforeIdx := -1
	proposals := make([]www.ProposalRecord, 0)

	// Iterate in reverse order because they're sorted by oldest timestamp
	// first.
	for i := len(allProposals) - 1; i >= 0; i-- {
		proposal := allProposals[i]

		// Filter by user if it's provided.
		if pr.UserId != "" && pr.UserId != proposal.UserId {
			continue
		}

		// Filter by the status.
		if val, ok := pr.StatusMap[proposal.Status]; !ok || !val {
			continue
		}

		if pageStarted {
			proposals = append(proposals, proposal)
			if len(proposals) >= www.ProposalListPageSize {
				break
			}
		} else if pr.After != "" {
			// The beginning of the page has been found, so
			// the next public proposal is added.
			pageStarted = proposal.CensorshipRecord.Token == pr.After
		} else if pr.Before != "" {
			// The end of the page has been found, so we'll
			// have to iterate in the other direction to
			// add the proposals; save the current index.
			if proposal.CensorshipRecord.Token == pr.Before {
				beforeIdx = i
				break
			}
		}
	}

	// If beforeIdx is set, the caller is asking for vetted proposals whose
	// last result is before the provided proposal.
	if beforeIdx >= 0 {
		for _, proposal := range allProposals[beforeIdx+1:] {
			// Filter by user if it's provided.
			if pr.UserId != "" && pr.UserId != proposal.UserId {
				continue
			}

			// Filter by the status.
			if val, ok := pr.StatusMap[proposal.Status]; !ok || !val {
				continue
			}

			// The iteration direction is oldest -> newest,
			// so proposals are prepended to the array so
			// the result will be newest -> oldest.
			proposals = append([]www.ProposalRecord{proposal},
				proposals...)
			if len(proposals) >= www.ProposalListPageSize {
				break
			}
		}
	}

	return proposals
}
