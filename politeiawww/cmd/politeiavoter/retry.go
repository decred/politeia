// Copyright (c) 2019-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/util"
)

type retry struct {
	retries uint
	vote    tkv1.CastVote
}

func (c *ctx) retryPush(r *retry) {
	c.Lock()
	defer c.Unlock()
	r.retries++
	c.retryQ.PushBack(r)
}

func (c *ctx) retryPop() *retry {
	c.Lock()
	defer c.Unlock()

	e := c.retryQ.Front()
	if e == nil {
		return nil
	}
	return c.retryQ.Remove(e).(*retry)
}

func (c *ctx) retryLen() int {
	c.Lock()
	defer c.Unlock()
	return c.retryQ.Len()
}

func (c *ctx) dumpQueue() {
	c.RLock()
	defer c.RUnlock()

	fmt.Printf("Retry votes remaining (%v):\n", c.retryQ.Len())
	for e := c.retryQ.Front(); e != nil; e = e.Next() {
		r := e.Value.(*retry)
		fmt.Printf("  %v %v\n", r.vote.Ticket, r.retries)
	}
}

func (c *ctx) retryLoop() {
	log.Debug("retryLoop: start of day")
	defer log.Debugf("retryLoop: end of times")
	defer c.retryWG.Done()

	mainLoopDone := false
	for {
		// Random timeout between 0 and 119 seconds
		wait, err := util.Random(1)
		if err != nil {
			// This really shouldn't happen so just use 33 seconds
			wait = []byte{33}
		} else {
			wait[0] = wait[0] % 120
		}

		select {
		case <-c.wctx.Done():
			return
		case <-c.mainLoopForceExit:
			// Main loop is forcing an exit
			fmt.Printf("Forced exit retry vote queue.\n")
			return
		case <-c.mainLoopDone:
			mainLoopDone = true
			// Fallthrough in case there is no more work. This way
			// the retryLoop exits right away.
		case <-time.After(time.Duration(wait[0]) * time.Second):
			log.Debugf("retryLoop: tick after %v mainLoopDone %v",
				time.Duration(wait[0])*time.Second,
				mainLoopDone)
		}

		e := c.retryPop()
		if e == nil {
			if mainLoopDone {
				// Main loop has exited
				log.Tracef("retryLoop: done ballotResults %v",
					spew.Sdump(c.ballotResults))
				break
			}
			// Nothing to do and main loop has not exited
			log.Debugf("retryLoop: nothing to do")
			continue
		}

		fmt.Printf("Retry vote (%v): %v\n", e.retries, e.vote.Ticket)

		// Vote
		ticket := e.vote.Ticket
		b := tkv1.CastBallot{Votes: []tkv1.CastVote{e.vote}}
		log.Debugf("retryLoop: sendVote %v", ticket)
		vr, err := c.sendVote(&b)
		var serr ErrRetry
		if errors.As(err, &serr) {
			// Push to back retry later
			fmt.Printf("Retry vote rescheduled: %v\n",
				e.vote.Ticket)
			log.Debugf("retryLoop: retry failed vote %v %v",
				ticket, serr)
			err := c.jsonLog("failed.json", e.vote.Token, b, serr)
			if err != nil {
				log.Errorf("retryLoop: c.jsonLog 1: %v", err)
				continue
			}
			c.retryPush(e)
			continue
		} else if err != nil {
			// XXX this may be too rough but shouldn't happen
			panic(fmt.Sprintf("permanently failed: %v %v",
				ticket, err))
		}

		// Vote completed
		c.Lock()
		c.ballotResults = append(c.ballotResults, *vr)
		c.Unlock()

		if vr.ErrorCode == tkv1.VoteErrorVoteStatusInvalid {
			// Force an exit of the both the main queue and the
			// retry queue if the voting period has ended.
			err = c.jsonLog("failed.json", ticket, vr)
			if err != nil {
				log.Errorf("retryLoop: c.jsonLog 2: %v", err)
			}
			fmt.Printf("Vote has ended; forced exit retry vote queue.\n")
			if !mainLoopDone {
				fmt.Printf("Awaiting main vote queue to exit.\n")
				c.retryLoopForceExit <- struct{}{}
			}
			return
		}

		err = c.jsonLog("success.json", e.vote.Token, vr)
		if err != nil {
			log.Errorf("retryLoop: c.jsonLog 3: %v", err)
			continue
		}

		log.Debugf("retryLoop: success %v", spew.Sdump(vr))

		// Check if we are done here as well
		if mainLoopDone && c.retryLen() == 0 {
			return
		}
	}
}
