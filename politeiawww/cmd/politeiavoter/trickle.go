package main

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"crypto/rand"

	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/util"
	"golang.org/x/sync/errgroup"
)

// WaitUntil will block until the given time.  Can be cancelled by cancelling
// the context
func WaitUntil(ctx context.Context, t time.Time) error {
	// This garbage is a fucking retarded lint idea.
	// We therefore replace the readable `diff := t.Sub(time.Now())` line
	// into unreadable time.Until() crap.
	diff := time.Until(t)
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

func (p *piv) generateVoteAlarm(votesToCast []tkv1.CastVote) ([]*voteAlarm, error) {
	bunches := int(p.cfg.Bunches)
	voteDuration := p.cfg.voteDuration
	fmt.Printf("Total number of votes  : %v\n", len(votesToCast))
	fmt.Printf("Total number of bunches: %v\n", bunches)
	fmt.Printf("Vote duration          : %v\n", voteDuration)

	// Initialize bunches
	tStart := make([]time.Time, bunches)
	tEnd := make([]time.Time, bunches)
	for i := 0; i < bunches; i++ {
		var err error
		tStart[i], tEnd[i], err = randomTime(voteDuration)
		if err != nil {
			return nil, err
		}
		fmt.Printf("bunchID: %v start %v end %v duration %v\n",
			i, tStart[i], tEnd[i], tEnd[i].Sub(tStart[i]))
	}

	va := make([]*voteAlarm, len(votesToCast))
	for k := range votesToCast {
		x := k % bunches
		start := new(big.Int).SetInt64(tStart[x].Unix())
		end := new(big.Int).SetInt64(tEnd[x].Unix())
		// Generate random time to fire off vote
		r, err := rand.Int(rand.Reader, new(big.Int).Sub(end, start))
		if err != nil {
			return nil, err
		}
		//fmt.Printf("r        : %v\n", r)
		t := time.Unix(tStart[x].Unix()+r.Int64(), 0)
		//fmt.Printf("at time  : %v\n", t)

		va[k] = &voteAlarm{
			Vote: votesToCast[k],
			At:   t,
		}
	}

	return va, nil
}

// randomDuration returns a randomly selected Duration between the provided
// min and max (in seconds).
func randomDuration(min, max byte) time.Duration {
	var (
		wait []byte
		err  error
	)
	for {
		wait, err = util.Random(1)
		if err != nil {
			// This really shouldn't happen so just use min seconds
			wait = []byte{min}
		} else {
			if wait[0] < min || wait[0] > max {
				continue
			}
			//fmt.Printf("min %v max %v got %v\n", min, max, wait[0])
		}
		break
	}
	return time.Duration(wait[0]) * time.Second
}

func (p *piv) voteTicket(ectx context.Context, bunchID, voteID, of int, va voteAlarm) error {
	voteID++ // make human readable

	// Wait
	err := WaitUntil(ectx, va.At)
	if err != nil {
		return fmt.Errorf("%v bunch %v vote %v failed: %v",
			time.Now(), bunchID, voteID, err)
	}

	// Vote
	for retry := 0; ; retry++ {
		var rmsg string
		if retry != 0 {
			// Wait between 1 and 17 seconds
			d := randomDuration(3, 17)
			rmsg = fmt.Sprintf("retry %v (%v) ", retry, d)
			err = WaitFor(ectx, d)
			if err != nil {
				return fmt.Errorf("%v bunch %v vote %v failed: %v",
					time.Now(), bunchID, voteID, err)
			}
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
				return fmt.Errorf("0 jsonLog: %v", err)
			}

			// Retry
			continue

		} else if err != nil {
			// Unrecoverable error
			return fmt.Errorf("unrecoverable error: %v",
				err)
		}

		// Evaluate errors when ErrorCode is set
		if vr.ErrorCode != nil {
			switch *vr.ErrorCode {
			// Silently ignore.
			case tkv1.VoteErrorTicketAlreadyVoted:
				// This happens during network errors. Since
				// the ticket has already voted record success
				// and exit.

			// Restart
			case tkv1.VoteErrorInternalError:
				// Politeia puked. Retry later to see if it
				// recovered.
				continue

			// Non-terminal errors
			case tkv1.VoteErrorTokenInvalid,
				tkv1.VoteErrorRecordNotFound,
				tkv1.VoteErrorMultipleRecordVotes,
				tkv1.VoteErrorVoteBitInvalid,
				tkv1.VoteErrorSignatureInvalid,
				tkv1.VoteErrorTicketNotEligible:

				// Log failure
				err = p.jsonLog(failedJournal, va.Vote.Token, vr)
				if err != nil {
					return fmt.Errorf("1 jsonLog: %v", err)
				}

				// We have to do this for all failures, this
				// should be rewritten.
				p.Lock()
				p.ballotResults = append(p.ballotResults, *vr)
				p.Unlock()

				return nil

			// Terminal
			case tkv1.VoteErrorVoteStatusInvalid:
				// Force an exit of the both the main queue and the
				// retry queue if the voting period has ended.
				err = p.jsonLog(failedJournal, va.Vote.Token, vr)
				if err != nil {
					return fmt.Errorf("2 jsonLog: %v", err)
				}
				return fmt.Errorf("Vote has ended; forced " +
					"exit main vote queue.")

			// Should not happen
			default:
				// Log failure
				err = p.jsonLog(failedJournal, va.Vote.Token, vr)
				if err != nil {
					return fmt.Errorf("3 jsonLog: %v", err)
				}

				// We have to do this for all failures, this
				// should be rewritten.
				p.Lock()
				p.ballotResults = append(p.ballotResults, *vr)
				p.Unlock()

				return nil
			}
		}

		// Success, log it and exit
		err = p.jsonLog(successJournal, va.Vote.Token, vr)
		if err != nil {
			return fmt.Errorf("3 jsonLog: %v", err)
		}

		// All done with this vote
		// Vote completed
		p.Lock()
		p.ballotResults = append(p.ballotResults, *vr)

		// This is required to be in the lock to prevent a
		// ballotResults race
		fmt.Printf("%v finished bunch %v vote %v -- "+
			"total progress %v/%v\n", time.Now(), bunchID,
			voteID, len(p.ballotResults), cap(p.ballotResults))
		p.Unlock()

		return nil
	}

	// Not reached
}

func randomInt64(min, max int64) (int64, error) {
	mi := new(big.Int).SetInt64(min)
	ma := new(big.Int).SetInt64(max)
	r, err := rand.Int(rand.Reader, new(big.Int).Sub(ma, mi))
	if err != nil {
		return 0, err
	}
	return new(big.Int).Add(mi, r).Int64(), nil
}

func randomTime(d time.Duration) (time.Time, time.Time, error) {
	now := time.Now()
	halfDuration := int64(d / 2)
	st, err := randomInt64(0, halfDuration*90/100) // up to 90% of half
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	et, err := randomInt64(halfDuration, int64(d))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	startTime := now.Add(time.Duration(st)).Unix()
	endTime := now.Add(time.Duration(et)).Unix()
	return time.Unix(startTime, 0), time.Unix(endTime, 0), nil
}

func (p *piv) alarmTrickler(token string, votesToCast []tkv1.CastVote) error {
	// Generate work queue
	votes, err := p.generateVoteAlarm(votesToCast)
	if err != nil {
		return err
	}

	// Log work
	err = p.jsonLog(workJournal, token, votes)
	if err != nil {
		return err
	}

	// Launch the voting stats handler
	go p.statsHandler()

	// Launch voting go routines
	eg, ectx := errgroup.WithContext(p.ctx)
	p.ballotResults = make([]tkv1.CastVoteReply, 0, len(votesToCast))
	div := len(votes) / int(p.cfg.Bunches)
	mod := len(votes) % int(p.cfg.Bunches)
	for k := range votes {
		voterID := k
		bunchID := voterID % int(p.cfg.Bunches)
		v := *votes[k]

		// Calculate of
		of := div
		if mod != 0 && bunchID == int(p.cfg.Bunches)-1 {
			of = mod
		}
		eg.Go(func() error {
			return p.voteTicket(ectx, bunchID, voterID, of, v)
		})
	}
	err = eg.Wait()
	if err != nil {
		//fmt.Printf("%v\n", err)
		return err
	}

	return nil
}
