package gitbe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/decred/dcrdata/dcrdataapi"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

var (
	decredPluginSettings map[string]string
)

func getDecredPlugin(testnet bool) backend.Plugin {
	decredPlugin := backend.Plugin{
		ID:       decredplugin.ID,
		Version:  decredplugin.Version,
		Settings: []backend.PluginSetting{
			//{
			//	Key:   "dcrd",
			//	Value: "localhost:19109",
			//},
			//{
			//	Key:   "dcrduser",
			//	Value: "u",
			//},
			//{
			//	Key:   "dcrdpass",
			//	Value: "p",
			//},
		},
	}

	if testnet {
		decredPlugin.Settings = append(decredPlugin.Settings,
			backend.PluginSetting{
				Key:   "dcrdata",
				Value: "https://testnet.dcrdata.org:443/",
			},
		)
	} else {
		decredPlugin.Settings = append(decredPlugin.Settings,
			backend.PluginSetting{
				Key:   "dcrdata",
				Value: "https://dcrdata.org:443/",
			})
	}

	// Initialize settings map
	decredPluginSettings = make(map[string]string)
	for _, v := range decredPlugin.Settings {
		decredPluginSettings[v.Key] = v.Value
	}

	return decredPlugin
}

func bestBlock() (*dcrdataapi.BlockDataBasic, error) {
	url := decredPluginSettings["dcrdata"] + "api/block/best"
	log.Debugf("connecting to %v", url)
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var bdb dcrdataapi.BlockDataBasic
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bdb); err != nil {
		return nil, err
	}

	return &bdb, nil
}

func block(block uint32) (*dcrdataapi.BlockDataBasic, error) {
	h := strconv.FormatUint(uint64(block), 10)
	url := decredPluginSettings["dcrdata"] + "api/block/" + h
	log.Debugf("connecting to %v", url)
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var bdb dcrdataapi.BlockDataBasic
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bdb); err != nil {
		return nil, err
	}

	return &bdb, nil
}

func snapshot(hash string) ([]string, error) {
	url := decredPluginSettings["dcrdata"] + "api/stake/pool/b/" + hash +
		"/full?sort=true"
	log.Debugf("connecting to %v", url)
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var tickets []string
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&tickets); err != nil {
		return nil, err
	}

	return tickets, nil
}

func largestCommitmentAddress(hash string) (string, error) {
	url := decredPluginSettings["dcrdata"] + "api/tx/" + hash
	log.Infof("connecting to %v", url)
	log.Debugf("connecting to %v", url)
	r, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	var ttx dcrdataapi.TrimmedTx
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ttx); err != nil {
		return "", err
	}
	_ = ttx

	//log.Errorf("%v", spew.Sdump(ttx))
	return "fleh", nil
}

func (g *gitBackEnd) pluginBestBlock() (string, error) {
	bb, err := bestBlock()
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(uint64(bb.Height), 10), nil
}

func (g *gitBackEnd) pluginStartVote(payload string) (string, error) {
	vote, err := decredplugin.DecodeVote([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeVote %v", err)
	}

	// XXX verify vote bits are sane

	// XXX verify proposal exists

	// XXX verify proposal is in the right state

	token, err := util.ConvertStringToken(vote.Token)
	if err != nil {
		return "", fmt.Errorf("ConvertStringToken %v", err)
	}

	// 1. Get best block
	bb, err := bestBlock()
	if err != nil {
		return "", fmt.Errorf("bestBlock %v", err)
	}
	if bb.Height < uint32(g.activeNetParams.TicketMaturity) {
		return "", fmt.Errorf("invalid height")
	}
	// 2. Subtract TicketMaturity from block height to get into
	// unforkable teritory
	snapshotBlock, err := block(bb.Height -
		uint32(g.activeNetParams.TicketMaturity))
	if err != nil {
		return "", fmt.Errorf("bestBlock %v", err)
	}
	// 3. Get ticket pool snapshot
	snapshot, err := snapshot(snapshotBlock.Hash)
	if err != nil {
		return "", fmt.Errorf("snapshot %v", err)
	}

	duration := uint32(2016) // XXX 1 week on mainnet
	svr := decredplugin.StartVoteReply{
		StartBlockHeight: strconv.FormatUint(uint64(snapshotBlock.Height), 10),
		StartBlockHash:   snapshotBlock.Hash,
		EndHeight:        strconv.FormatUint(uint64(snapshotBlock.Height+duration), 10),
		EligibleTickets:  snapshot,
	}
	svrb, err := decredplugin.EncodeStartVoteReply(svr)
	if err != nil {
		return "", fmt.Errorf("EncodeStartVoteReply: %v", err)
	}

	// XXX store snapshot in metadata
	err = g.UpdateVettedMetadata(token, nil, []backend.MetadataStream{
		{
			ID:      decredplugin.MDStreamVoteBits,
			Payload: payload, // Contains incoming vote request
		},
		{
			ID:      decredplugin.MDStreamVoteSnapshot,
			Payload: string(svrb),
		}})
	if err != nil {
		return "", fmt.Errorf("UpdateVettedMetadata: %v", err)
	}

	log.Infof("Vote started for: %v snapshot %v start %v end %v",
		vote.Token, svr.StartBlockHash, svr.StartBlockHeight,
		svr.EndHeight)

	// return success and encoded answer
	return string(svrb), nil
}

func (g *gitBackEnd) pluginCastVotes(payload string) (string, error) {
	log.Infof("pluginCastVotes: %v", payload)
	vote, err := decredplugin.DecodeCastVotes([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeVote %v", err)
	}

	// Go over all votes and verify signature
	log.Infof("pluginCastVotes 1")
	for _, v := range vote {
		// Figure out addresses
		log.Infof("pluginCastVotes 2")
		addr, err := largestCommitmentAddress(v.Ticket)
		if err != nil {
			return "", err
		}
		_ = addr

		// Recreate message
		msg := v.Token + v.Ticket + v.VoteBit

		// Verify message
		_ = msg
	}

	return "NOT YET...", fmt.Errorf("not yet...")
}
