package main

import (
	"container/list"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "decred.org/dcrwallet/rpc/walletrpc"
)

func fakeTickets(x int) (*pb.CommittedTicketsResponse, *pb.SignMessagesResponse) {
	ctres := pb.CommittedTicketsResponse{
		TicketAddresses: make([]*pb.CommittedTicketsResponse_TicketAddress, x),
	}
	for k := range ctres.TicketAddresses {
		ctres.TicketAddresses[k] = &pb.CommittedTicketsResponse_TicketAddress{
			Ticket: make([]byte, 32),
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

func fakeCtx(t *testing.T, d time.Duration, x int) (*ctx, func()) {
	// Setup temp home dir
	homeDir, err := ioutil.TempDir("", "politeiavoter.test")
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		err = os.RemoveAll(homeDir)
		if err != nil {
			t.Fatal(err)
		}
	}

	return &ctx{
		cfg: &config{
			HomeDir:      homeDir,
			voteDir:      filepath.Join(homeDir, defaultVoteDirname),
			voteDuration: d,
		},
		voteIntervalQ: new(list.List),
	}, cleanup
}

func TestTrickleNotEnoughTime(t *testing.T) {
	x := 10
	c, cleanup := fakeCtx(t, time.Hour, x)
	defer cleanup()

	ctres, smr := fakeTickets(x)
	err := c.calculateTrickle("", "", ctres, smr)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTrickle2(t *testing.T) {
	x := 10
	c, cleanup := fakeCtx(t, 24*time.Hour, x)
	defer cleanup()

	ctres, smr := fakeTickets(x)
	err := c.calculateTrickle("", "", ctres, smr)
	if err != nil {
		t.Fatal(err)
	}
}
