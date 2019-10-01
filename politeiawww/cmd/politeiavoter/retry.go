// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/davecgh/go-spew/spew"
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

func (c *ctx) dumpQueue() {
	c.RLock()
	defer c.RUnlock()

	for e := c.retryQ.Front(); e != nil; e = e.Next() {
		fmt.Printf("Retry votes remaining (%v):\n", c.retryQ.Len())
		r := e.Value.(*retry)
		fmt.Printf("  %v %v:\n", r.vote.Ticket, r.retries)
	}
}

func (c *ctx) signalHandler(signals chan os.Signal, done chan struct{}) {
	for {
		select {
		case <-signals:
			c.dumpQueue()
		case <-done:
			return
		}
	}
}

func (c *ctx) retryLoop(vr *v1.BallotReply, tickets *[]string) {
	log.Debug("retryLoop: start of day")
	defer log.Debugf("retryLoop: end of times")
	defer c.retryWG.Done()

	signals := make(chan os.Signal, 1)
	signalsDone := make(chan struct{}, 1)
	defer func() {
		signal.Stop(signals)
		close(signalsDone)
	}()
	signal.Notify(signals, syscall.SIGUSR1)
	go c.signalHandler(signals, signalsDone)

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
		case <-c.c:
			break
		case <-c.mainLoopDone:
			mainLoopDone = true
		case <-time.After(time.Duration(wait[0]) * time.Second):
			log.Debugf("retryLoop: tick after %v mainLoopDone %v",
				time.Duration(wait[0])*time.Second,
				mainLoopDone)
		}

		e := c.retryPop()
		if e == nil {
			if mainLoopDone {
				// Main loop has exited
				log.Debugf("retryLoop: done")
				log.Debugf("retryLoop: done tickets %v", spew.Sdump(tickets))
				log.Debugf("retryLoop: done vr %v", spew.Sdump(vr))
				break
			}
			// Nothing to do and main loop has not exited
			log.Debugf("retryLoop: nothing to do")
			continue
		}

		// Vote
		token := e.vote.Token
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
			log.Debugf("retryLoop: retry failed vote %v %v",
				ticket, serr)
			err := c.jsonLog("failed.json", token, b)
			if err != nil {
				log.Errorf("retryLoop: c.jsonLog 1: %v", err)
				continue
			}
			err = c.jsonLog("failed.json", token, serr)
			if err != nil {
				log.Errorf("retryLoop: c.jsonLog 2: %v", err)
				continue
			}
			c.retryPush(e)
			continue
		} else if err != nil {
			// XXX this may be too rough but shouldn't happen
			panic(fmt.Sprintf("permanently failed: %v %v",
				ticket, err))
		}

		// journal result
		err = c.jsonLog("success.json", token, *br)
		if err != nil {
			log.Errorf("retryLoop: c.jsonLog 3: %v", err)
			continue
		}

		log.Debugf("retryLoop: success %v", spew.Sdump(br))

		// Vote succeeded
		c.Lock()
		// Record receipt
		vr.Receipts = append(vr.Receipts, *br)
		// Append ticket to return value
		*tickets = append(*tickets, e.vote.Ticket)
		c.Unlock()
	}
}
