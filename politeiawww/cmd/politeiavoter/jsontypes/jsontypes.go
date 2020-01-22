package jsontypes

import (
	"fmt"
	"time"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
)

// Timestamp is always the first record of any file.
type Timestamp struct {
	Time string `json:"time"`
}

// VoteInterval is an internal structure that is used to precalculate all
// timing intervals and vote details. This is a JSON structure for logging
// purposes.
type VoteInterval struct {
	Vote  v1.CastVote   `json:"vote"`  // RPC vote
	Votes int           `json:"votes"` // Always 1 for now
	Total time.Duration `json:"total"` // Cumulative time
	At    time.Duration `json:"at"`    // Delay to fire off vote
}

// BallotResult is a tupple of the ticket and receipt. We combine the too
// because CastVoteReply does not contain the ticket address.
type BallotResult struct {
	Ticket  string           `json:"ticket"`  // ticket address
	Receipt v1.CastVoteReply `json:"receipt"` // result of vote
}

// ErrRetry is an internal error used to restart a vote.
type ErrRetry struct {
	At   string `json:"at"`   // where in the code
	Body []byte `json:"body"` // http body if we have one
	Code int    `json:"code"` // http code
	Err  error  `json:"err"`  // underlying error
}

func (e ErrRetry) Error() string {
	return fmt.Sprintf("retry error: %v (%v) %v", e.Code, e.At, e.Err)
}
