// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testpoliteiad

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	decred "github.com/decred/politeia/decredplugin"
	v1 "github.com/decred/politeia/politeiad/api/v1"
)

const (
	bestBlock uint32 = 1000
)

func (p *TestPoliteiad) authorizeVote(payload string) (string, error) {
	av, err := decred.DecodeAuthorizeVote([]byte(payload))
	if err != nil {
		return "", err
	}

	// Sign authorize vote
	s := p.identity.SignMessage([]byte(av.Signature))
	av.Receipt = hex.EncodeToString(s[:])
	av.Timestamp = time.Now().Unix()
	av.Version = decred.VersionAuthorizeVote

	p.Lock()
	defer p.Unlock()

	// Store authorize vote
	_, ok := p.authorizeVotes[av.Token]
	if !ok {
		p.authorizeVotes[av.Token] = make(map[string]decred.AuthorizeVote)
	}

	r, err := p.record(av.Token)
	if err != nil {
		return "", err
	}

	p.authorizeVotes[av.Token][r.Version] = *av

	// Prepare reply
	avrb, err := decred.EncodeAuthorizeVoteReply(
		decred.AuthorizeVoteReply{
			Action:        av.Action,
			RecordVersion: r.Version,
			Receipt:       av.Receipt,
			Timestamp:     av.Timestamp,
		})
	if err != nil {
		return "", err
	}

	return string(avrb), nil
}

func (p *TestPoliteiad) startVote(payload string) (string, error) {
	sv, err := decred.DecodeStartVoteV2([]byte(payload))
	if err != nil {
		return "", err
	}

	p.Lock()
	defer p.Unlock()

	// Store start vote
	sv.Version = decred.VersionStartVote
	p.startVotes[sv.Vote.Token] = *sv

	// Prepare reply
	endHeight := bestBlock + sv.Vote.Duration
	svr := decred.StartVoteReply{
		Version:          decred.VersionStartVoteReply,
		StartBlockHeight: strconv.FormatUint(uint64(bestBlock), 10),
		EndHeight:        strconv.FormatUint(uint64(endHeight), 10),
		EligibleTickets:  []string{},
	}
	svrb, err := decred.EncodeStartVoteReply(svr)
	if err != nil {
		return "", err
	}

	// Store reply
	p.startVoteReplies[sv.Vote.Token] = svr

	return string(svrb), nil
}

func (p *TestPoliteiad) startVoteRunoff(payload string) (string, error) {
	svr, err := decred.DecodeStartVoteRunoff([]byte(payload))
	if err != nil {
		return "", err
	}

	p.Lock()
	defer p.Unlock()

	// Store authorize votes
	avReply := make(map[string]decred.AuthorizeVoteReply)
	for _, av := range svr.AuthorizeVotes {
		r, err := p.record(av.Token)
		if err != nil {
			return "", err
		}
		// Fill client data
		s := p.identity.SignMessage([]byte(av.Signature))
		av.Version = decred.VersionAuthorizeVote
		av.Receipt = hex.EncodeToString(s[:])
		av.Timestamp = time.Now().Unix()
		av.Version = decred.VersionAuthorizeVote

		// Store
		_, ok := p.authorizeVotes[av.Token]
		if !ok {
			p.authorizeVotes[av.Token] = make(map[string]decred.AuthorizeVote)
		}
		p.authorizeVotes[av.Token][r.Version] = av

		// Prepare response
		avr := decred.AuthorizeVoteReply{
			Action:        av.Action,
			RecordVersion: r.Version,
			Receipt:       av.Receipt,
			Timestamp:     av.Timestamp,
		}
		avReply[av.Token] = avr
	}

	// Store start votes
	svReply := decred.StartVoteReply{}
	for _, sv := range svr.StartVotes {
		sv.Version = decred.VersionStartVote
		p.startVotes[sv.Vote.Token] = sv
		// Prepare response
		endHeight := bestBlock + sv.Vote.Duration
		svReply.Version = decred.VersionStartVoteReply
		svReply.StartBlockHeight = strconv.FormatUint(uint64(bestBlock), 10)
		svReply.EndHeight = strconv.FormatUint(uint64(endHeight), 10)
		svReply.EligibleTickets = []string{}
	}

	// Store start vote runoff
	p.startVotesRunoff[svr.Token] = *svr

	response := decred.StartVoteRunoffReply{
		AuthorizeVoteReplies: avReply,
		StartVoteReply:       svReply,
	}

	p.startVotesRunoffReplies[svr.Token] = response

	svrReply, err := decred.EncodeStartVoteRunoffReply(response)
	if err != nil {
		return "", err
	}

	return string(svrReply), nil
}

// decredExec executes the passed in plugin command.
func (p *TestPoliteiad) decredExec(pc v1.PluginCommand) (string, error) {
	switch pc.Command {
	case decred.CmdStartVote:
		return p.startVote(pc.Payload)
	case decred.CmdStartVoteRunoff:
		return p.startVoteRunoff(pc.Payload)
	case decred.CmdAuthorizeVote:
		return p.authorizeVote(pc.Payload)
	case decred.CmdBestBlock:
		return strconv.FormatUint(uint64(bestBlock), 10), nil
	case decred.CmdVoteSummary:
		// This is a cache plugin command. No work needed here.
		return "", nil
	}
	return "", fmt.Errorf("invalid testpoliteiad plugin command")
}
