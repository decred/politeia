package main

import (
	"container/list"
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

func fakeCtx(d time.Duration, x int) *ctx {
	return &ctx{
		cfg: &config{
			voteDuration: d,
		},
		voteIntervalQ: new(list.List),
	}
}

func TestTrickleNotEnoughTime(t *testing.T) {
	x := 10
	c := fakeCtx(time.Hour, x)
	ctres, smr := fakeTickets(x)
	err := c.calculateTrickle("", "", ctres, smr)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTrickle2(t *testing.T) {
	x := 10
	c := fakeCtx(24*time.Hour, x)
	ctres, smr := fakeTickets(x)
	err := c.calculateTrickle("", "", ctres, smr)
	if err != nil {
		t.Fatal(err)
	}
}
