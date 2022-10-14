package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
)

const keepFiles = false

func fakeVotesToCast(x uint) []tkv1.CastVote {
	fakeSignature := hex.EncodeToString(make([]byte, 64))
	votesToCast := make([]tkv1.CastVote, 0, x)
	for i := uint(0); i < x; i++ {
		var ticket [chainhash.HashSize]byte
		binary.LittleEndian.PutUint64(ticket[:], uint64(i))
		ticketHash := chainhash.Hash(ticket)
		votesToCast = append(votesToCast, tkv1.CastVote{
			Token:     "token",
			Ticket:    ticketHash.String(),
			VoteBit:   "voteBit",
			Signature: fakeSignature,
		})
	}

	return votesToCast
}

func fakePiv(t *testing.T, d time.Duration, x uint) (*piv, func()) {
	// Setup temp home dir
	homeDir, err := os.MkdirTemp("", "politeiavoter.test")
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
			Bunches:      x,
			testing:      true,
		},
	}, cleanup
}

func TestTrickleWorkers(t *testing.T) {
	bunches := uint(3)
	c, cleanup := fakePiv(t, time.Minute, bunches)
	defer cleanup()

	nrVotes := uint(20)
	err := c.alarmTrickler("token", fakeVotesToCast(nrVotes))
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnrecoverableTrickleWorkers(t *testing.T) {
	c, cleanup := fakePiv(t, 10*time.Second, 1)
	defer cleanup()

	c.cfg.testingMode = testFailUnrecoverable

	err := c.alarmTrickler("token", fakeVotesToCast(1))
	if err == nil {
		t.Fatal("expected unrecoverable error")
	}
}

func TestManyTrickleWorkers(t *testing.T) {
	if testing.Short() {
		t.Skip("TestManyTrickleWorkers: skipping test in short mode.")
	}

	bunches := uint(10)
	c, cleanup := fakePiv(t, 2*time.Minute, bunches)
	defer cleanup()

	nrVotes := uint(20000)
	err := c.alarmTrickler("token", fakeVotesToCast(nrVotes))
	if err != nil {
		t.Fatal(err)
	}
}
