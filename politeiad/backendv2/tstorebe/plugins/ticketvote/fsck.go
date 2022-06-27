// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// fsck performs the ticketvote plugin file system check. The following checks
// are performed:
//
// 1. Rebuild the vote summaries cache. Records that have finished voting
//    will have a vote summary saved to the cache. This cache is rebuilt
//    from scratch.
//
// 2. Rebuild the vote inventory cache. All vetted records are included in the
//    vote inventory cache. This cache is rebuilt from scratch.
//
// 3. Rebuild the runoff vote submissions cache. The submissions cache contains
//    the list of runoff vote parent records and all of their runoff vote
//    submissions. This cache is built from scratch.
func (p *ticketVotePlugin) fsck(tokens [][]byte) error {
	log.Infof("Starting ticketvote fsck for %v records", len(tokens))

	// Filter out the vetted records. The ticketvote plugin
	// commands can only be run on vetted records.
	vetted := make([][]byte, 0, len(tokens))
	for _, token := range tokens {
		state, err := p.tstore.RecordState(token)
		if err != nil {
			return err
		}
		if state == backend.StateVetted {
			vetted = append(vetted, token)
		}
	}

	log.Infof("%v vetted records found", len(vetted))

	// 1. Rebuild the vote summaries cache.
	//
	// Records that have finished voting will have a vote summary saved
	// to the cache. The summary() function builds the vote summary from
	// scratch for a record and saves it to the cache when appropriate.
	// The only thing we need to do to rebuild the vote summaries cache
	// is to delete existing entries and then invoke the summary()
	// function on all vetted records.

	log.Infof("Building the vote summaries cache")

	bestBlock, err := p.bestBlock()
	if err != nil {
		return err
	}

	summaries := make(map[string]*ticketvote.SummaryReply, len(vetted))
	for i, tokenB := range vetted {
		// Building a vote summary requires retrieving various pieces
		// of data from the database. This is expensive. Log progress
		// every 5 records.
		if i%5 == 0 {
			log.Infof("Vote summaries cache progress %v/%v", i, len(vetted))
		}
		token := tokenEncode(tokenB)
		err = p.summaries.Del(token)
		if err != nil {
			return err
		}
		s, err := p.summary(tokenB, bestBlock)
		if err != nil {
			return err
		}
		summaries[token] = s
	}

	log.Infof("Vote summaries cache complete")

	// 2. Rebuild the vote inventory cache.
	//
	// All vetted records are included in the vote inventory cache.
	// This cache is built from scratch.

	log.Infof("Building the vote inventory cache")

	entries := make([]invEntry, 0, len(summaries))
	for token, v := range summaries {
		e := newInvEntry(token, v.Status, v.Timestamp, v.EndBlockHeight)
		entries = append(entries, *e)
	}
	p.inv.Rebuild(entries)

	log.Infof("Vote inventory cache complete")

	// 3. Rebuild the runoff vote submissions cache.
	//
	// The submissions cache contains the list of runoff vote parent
	// records and all of their runoff vote submissions. This cache
	// is built from scratch.
	log.Infof("Building the runoff vote submissions cache")

	err = p.rebuildSubsCache(vetted)
	if err != nil {
		return err
	}

	log.Info("Runoff vote submissions cache complete")

	return nil
}

// rebuildSubsCache rebuilds the runoff vote submissions cache from scratch.
//
// The provided list of tokens should include all runoff vote parent records
// as well as all runoff vote submissions. The cache is not rebuilt for any
// parent records that are not included in the list.
func (p *ticketVotePlugin) rebuildSubsCache(tokens [][]byte) error {
	// Compile the vote metadata of all runoff vote parents and
	// submissions.
	voteMD := make(map[string]*ticketvote.VoteMetadata, len(tokens))
	for _, tokenB := range tokens {
		r, err := p.recordAbridged(tokenB)
		if err != nil {
			return err
		}
		vmd, err := voteMetadataDecode(r.Files)
		if err != nil {
			return err
		}
		if !isRunoffParent(vmd) && !isRunoffSub(vmd) {
			// Not a runoff vote parent or submission
			continue
		}
		if r.RecordMetadata.Status != backend.StatusPublic {
			// Only public records are included in
			// the runoff vote submissions cache.
			continue
		}

		voteMD[tokenEncode(tokenB)] = vmd
	}

	// Delete all existing cache entries
	for token, v := range voteMD {
		if !isRunoffParent(v) {
			continue
		}
		err := p.subs.DelEntry(token)
		if err != nil {
			return err
		}
	}

	// Build the cache from scratch
	for token, v := range voteMD {
		if !isRunoffSub(v) {
			continue
		}
		p.subs.Add(v.LinkTo, token)
	}

	return nil
}
