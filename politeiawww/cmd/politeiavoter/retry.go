// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/decredplugin"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

type retry struct {
	retries uint
	vote    v1.CastVote
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
		wait[0] = 30 // XXX

		select {
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
		b := v1.Ballot{Votes: []v1.CastVote{e.vote}}
		var (
			br *v1.CastVoteReply
		)
		if e.retries > 1 {
			log.Debugf("retryLoop: sendVote %v", ticket)
			br, err = c.sendVote(&b)
		} else {
			log.Debugf("retryLoop: sendVoteFail %v", ticket)
			br, err = c.sendVoteFail(&b)
		}
		if serr, ok := err.(ErrRetry); ok {
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
		result := BallotResult{
			Ticket:  ticket,
			Receipt: *br,
		}
		c.Lock()
		c.ballotResults = append(c.ballotResults, result)
		c.Unlock()

		if br.ErrorStatus == decredplugin.ErrorStatusVoteHasEnded {
			// Force an exit of the both the main queue and the
			// retry queue if the voting period has ended.
			err = c.jsonLog("failed.json", ticket, br)
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

		err = c.jsonLog("success.json", e.vote.Token, result)
		if err != nil {
			log.Errorf("retryLoop: c.jsonLog 3: %v", err)
			continue
		}

		log.Debugf("retryLoop: success %v", spew.Sdump(br))

		// Check if we are done here as well
		if mainLoopDone && c.retryLen() == 0 {
			return
		}
	}
}
