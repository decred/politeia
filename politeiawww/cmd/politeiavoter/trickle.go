package main

import (
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"crypto/rand"

	pb "decred.org/dcrwallet/rpc/walletrpc"
	"github.com/decred/dcrd/chaincfg/chainhash"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/cmd/politeiavoter/uniformprng"
)

func (c *ctx) calculateTrickle(token, voteBit string, ctres *pb.CommittedTicketsResponse, smr *pb.SignMessagesResponse) error {
	votes := len(ctres.TicketAddresses)
	duration := c.cfg.voteDuration
	voteDuration := duration - time.Hour
	if voteDuration < time.Hour {
		return fmt.Errorf("not enough time left to trickle votes")
	}
	fmt.Printf("Total number of votes: %v\n", votes)
	fmt.Printf("Total vote duration  : %v\n", duration)
	fmt.Printf("Duration calculated  : %v\n", voteDuration)

	prng, err := uniformprng.RandSource(rand.Reader)
	if err != nil {
		return err
	}

	ts := make([]time.Duration, 0, votes)
	for i := 0; i < votes; i++ {
		ts = append(ts, time.Duration(prng.Int63n(int64(voteDuration))))
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	var previous, t time.Duration

	buckets := make([]*voteInterval, votes)
	for k := range ts {
		// Assemble missing vote bits
		h, err := chainhash.NewHash(ctres.TicketAddresses[k].Ticket)
		if err != nil {
			return err
		}
		signature := hex.EncodeToString(smr.Replies[k].Signature)

		buckets[k] = &voteInterval{
			Vote: tkv1.CastVote{
				Token:     token,
				Ticket:    h.String(),
				VoteBit:   voteBit,
				Signature: signature,
			},
			At: ts[k] - previous, // Delta to previous timestamp
		}
		t += ts[k] - previous
		previous = ts[k]
	}

	// Should not happen
	if t > voteDuration {
		return fmt.Errorf("assert t > voteDuration - %v > %v",
			t, voteDuration)
	}

	// Sanity
	if len(buckets) != len(ctres.TicketAddresses) {
		return fmt.Errorf("unexpected time bucket count got "+
			"%v, wanted %v", len(ctres.TicketAddresses),
			len(buckets))
	}

	// Convert buckets to a list
	for _, v := range buckets {
		c.voteIntervalPush(v)
	}

	// Log work
	err = c.jsonLog(workJournal, token, buckets)
	if err != nil {
		return err
	}

	return nil
}
