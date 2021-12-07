package main

import (
	"context"
	"encoding/binary"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "decred.org/dcrwallet/rpc/walletrpc"
)

const keepFiles = false

func fakeTickets(x uint) (*pb.CommittedTicketsResponse, *pb.SignMessagesResponse) {
	ctres := pb.CommittedTicketsResponse{
		TicketAddresses: make([]*pb.CommittedTicketsResponse_TicketAddress, x),
	}
	for k := range ctres.TicketAddresses {
		ticket := make([]byte, 32)
		binary.LittleEndian.PutUint64(ticket[:], uint64(k))
		ctres.TicketAddresses[k] = &pb.CommittedTicketsResponse_TicketAddress{
			Ticket: ticket,
		}
	}
	smr := pb.SignMessagesResponse{
		Replies: make([]*pb.SignMessagesResponse_SignReply, x),
	}
	for k := range smr.Replies {
		smr.Replies[k] = &pb.SignMessagesResponse_SignReply{
			Signature: make([]byte, 64),
		}
	}

	return &ctres, &smr
}

func fakePiv(t *testing.T, d time.Duration, x uint, hoursPrior uint64) (*piv, func()) {
	// Setup temp home dir
	homeDir, err := ioutil.TempDir("", "politeiavoter.test")
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		if keepFiles {
			t.Logf("Files not deleted from: %v", homeDir)
			return
		}
		err = os.RemoveAll(homeDir)
		if err != nil {
			t.Fatal(err)
		}
	}

	return &piv{
		ctx: context.Background(),
		run: time.Now(),
		cfg: &config{
			HomeDir:      homeDir,
			voteDir:      filepath.Join(homeDir, defaultVoteDirname),
			voteDuration: d,
			HoursPrior:   &hoursPrior,
			Bunches:      x,
			testing:      true,
		},
	}, cleanup
}

func TestTrickleNotEnoughTime(t *testing.T) {
	x := uint(10)
	c, cleanup := fakePiv(t, time.Hour, x, 1)
	defer cleanup()

	ctres, smr := fakeTickets(x)
	err := c.alarmTrickler("token", "voteBit", ctres, smr)
	t.Logf("error received: %v", err)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTrickleWorkers(t *testing.T) {
	bunches := uint(3)
	c, cleanup := fakePiv(t, time.Minute, bunches, 0)
	defer cleanup()

	nrVotes := uint(20)
	ctres, smr := fakeTickets(nrVotes)
	err := c.alarmTrickler("token", "voteBit", ctres, smr)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnrecoverableTrickleWorkers(t *testing.T) {
	c, cleanup := fakePiv(t, 10*time.Second, 1, 0)
	defer cleanup()

	c.cfg.testingMode = testFailUnrecoverable

	ctres, smr := fakeTickets(1)
	err := c.alarmTrickler("token", "voteBit", ctres, smr)
	if err == nil {
		t.Fatal("expected unrecoverable error")
	}
}

func TestManyTrickleWorkers(t *testing.T) {
	if testing.Short() {
		t.Skip("TestManyTrickleWorkers: skipping test in short mode.")
	}

	bunches := uint(10)
	c, cleanup := fakePiv(t, 2*time.Minute, bunches, 0)
	defer cleanup()

	nrVotes := uint(20000)
	ctres, smr := fakeTickets(nrVotes)
	err := c.alarmTrickler("token", "voteBit", ctres, smr)
	if err != nil {
		t.Fatal(err)
	}
}
