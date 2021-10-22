package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"crypto/rand"

	pb "decred.org/dcrwallet/rpc/walletrpc"
	"github.com/decred/dcrd/chaincfg/chainhash"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
)

// WaitUntil will block until the given time.  Can be cancelled by cancelling
// the context
func WaitUntil(ctx context.Context, t time.Time) error {
	diff := t.Sub(time.Now())
	if diff <= 0 {
		return nil
	}

	return WaitFor(ctx, diff)
}

// WaitFor will block for the specified duration or the context is cancelled
func WaitFor(ctx context.Context, diff time.Duration) error {
	timer := time.NewTimer(diff)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// voteAlarm represents a vote and the time at which it will be initially
// submitted to politeia.
type voteAlarm struct {
	Vote tkv1.CastVote `json:"vote"` // RPC vote
	At   time.Time     `json:"at"`   // When initial vote will be submitted
}

func generateVoteAlarm(token, voteBit string, ctres *pb.CommittedTicketsResponse, smr *pb.SignMessagesResponse) ([]*voteAlarm, error) {
	// Assert arrays are same length.
	if len(ctres.TicketAddresses) != len(smr.Replies) {
		return nil, fmt.Errorf("assert len(TicketAddresses) != "+
			"len(Replies) -- %v != %v", len(ctres.TicketAddresses),
			len(smr.Replies))
	}

	// Generate voteAlarm array
	now := time.Now()                           // XXX generate N now() based on the number of bunches
	startTime := now.Add(time.Second).Unix()    // XXX randomize
	endTime := now.Add(10 * time.Second).Unix() // XXX randomize
	start := new(big.Int).SetInt64(startTime)
	end := new(big.Int).SetInt64(endTime)
	//fmt.Printf("now      : %v\n", now)
	//fmt.Printf("startTime: %v\n", startTime)
	//fmt.Printf("endTime  : %v\n", endTime)
	//fmt.Printf("start    : %v\n", start)
	//fmt.Printf("end      : %v\n", end)

	va := make([]*voteAlarm, len(ctres.TicketAddresses))
	for k := range ctres.TicketAddresses {
		// Generate random time to fire off vote
		r, err := rand.Int(rand.Reader, new(big.Int).Sub(end, start))
		if err != nil {
			return nil, err
		}
		//fmt.Printf("r        : %v\n", r)
		t := time.Unix(startTime+r.Int64(), 0)
		//fmt.Printf("at time  : %v\n", t)

		// Assemble missing vote bits
		h, err := chainhash.NewHash(ctres.TicketAddresses[k].Ticket)
		if err != nil {
			return nil, err
		}
		signature := hex.EncodeToString(smr.Replies[k].Signature)
		va[k] = &voteAlarm{
			Vote: tkv1.CastVote{
				Token:     token,
				Ticket:    h.String(),
				VoteBit:   voteBit,
				Signature: signature,
			},
			At: t,
		}
	}

	return va, nil
}

func (p *piv) voteTicket(wg *sync.WaitGroup, bunchID, voteID, of int, va voteAlarm) {
	defer wg.Done()

	voteID++ // make human readable
	//fmt.Printf("bunchID: %v voterID: %v\n", bunchID, voteID)

	// Wait
	err := WaitUntil(p.ctx, va.At)
	if err != nil {
		fmt.Printf("%v bunch %v vote %v failed: %v\n",
			time.Now(), bunchID, voteID, err)
		return
	}

	// Vote
	for retry := 0; ; retry++ {
		var rmsg string
		if retry != 0 {
			// XXX sleep to retry
			time.Sleep(time.Second) // XXX randomize
			rmsg = fmt.Sprintf("retry %v ", retry)
		}

		fmt.Printf("%v voting bunch %v vote %v %v%v\n",
			time.Now(), bunchID, voteID, rmsg, va.Vote.Ticket)

		// Send off vote
		b := tkv1.CastBallot{Votes: []tkv1.CastVote{va.Vote}}
		vr, err := p.sendVote(&b)
		var e ErrRetry
		if errors.As(err, &e) {
			// Append failed vote to retry queue
			fmt.Printf("Vote rescheduled: %v\n", va.Vote.Ticket)
			err := p.jsonLog(failedJournal, va.Vote.Token, b, e)
			if err != nil {
				panic(err) // XXX
			}

			// Drop to retry loop

		} else if err != nil {
			// Unrecoverable error
			panic(fmt.Errorf("unrecoverable error: %v",
				err)) // XXX
		} else {
			// Vote completed
			p.Lock()
			p.ballotResults = append(p.ballotResults, *vr)
			p.Unlock()

			if vr.ErrorCode == tkv1.VoteErrorVoteStatusInvalid {
				// Force an exit of the both the main queue and the
				// retry queue if the voting period has ended.
				err = p.jsonLog(failedJournal, va.Vote.Token, vr)
				if err != nil {
					panic(err) // XXX
				}
				fmt.Printf("Vote has ended; forced exit main vote queue.\n")
				fmt.Printf("XXX CANCEL")
				return
			}

			err = p.jsonLog(successJournal, va.Vote.Token, vr)
			if err != nil {
				panic(err)
			}

			// All done with this vote
			fmt.Printf("%v finished bunch %v vote %v\n",
				time.Now(), bunchID, voteID)
			return
		}
	}

	// Not reached
}

func (p *piv) alarmTrickler(token, voteBit string, ctres *pb.CommittedTicketsResponse, smr *pb.SignMessagesResponse) error {
	votes, err := generateVoteAlarm(token, voteBit, ctres, smr)
	if err != nil {
		return err
	}

	bunches := int(p.cfg.Bunches)
	duration := p.cfg.voteDuration
	voteDuration := duration - time.Duration(p.cfg.HoursPrior)*time.Hour
	if voteDuration < time.Duration(p.cfg.HoursPrior)*time.Hour {
		return fmt.Errorf("not enough time left to trickle votes")
	}
	fmt.Printf("Total number of votes  : %v\n", len(ctres.TicketAddresses))
	fmt.Printf("Total number of bunches: %v\n", bunches)
	fmt.Printf("Total vote duration    : %v\n", duration)
	fmt.Printf("Duration calculated    : %v\n", voteDuration)

	// Log work
	err = p.jsonLog(workJournal, token, votes)
	if err != nil {
		return err
	}

	// Launch voting go routines
	var wg sync.WaitGroup
	p.ballotResults = make([]tkv1.CastVoteReply, len(ctres.TicketAddresses))
	for k := range votes {
		voterID := k
		bunchID := voterID % bunches
		v := *votes[k]
		wg.Add(1)
		go p.voteTicket(&wg, bunchID, voterID, len(votes), v)
	}
	wg.Wait()

	return nil
}
