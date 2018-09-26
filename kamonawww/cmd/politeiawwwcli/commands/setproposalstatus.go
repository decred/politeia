package commands

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/decred/politeia/politeiawww/api/v1"
)

type SetProposalStatusCmd struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true" description:"Proposal censorship record token"`
		Status  string `positional-arg-name:"status" required:"true" description:"New proposal status (censored or public)"`
		Message string `positional-arg-name:"message" description:"Status change message (required if censoring proposal)"`
	} `positional-args:"true"`
}

func (cmd *SetProposalStatusCmd) Execute(args []string) error {
	PropStatus := map[string]v1.PropStatusT{
		"censored": 3,
		"public":   4,
	}

	// Validate user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Parse proposal status.  This can be either the numeric
	// status code or the human readable equivalent.
	var status v1.PropStatusT
	s, err := strconv.ParseUint(cmd.Args.Status, 10, 32)
	if err == nil {
		// Numeric status code found
		status = v1.PropStatusT(s)
	} else if s, ok := PropStatus[cmd.Args.Status]; ok {
		// Human readable status code found
		status = s
	} else {
		return fmt.Errorf("Invalid proposal status.  Valid statuses are:\n  " +
			"censored    censor a proposal\n  " +
			"public      make a proposal public")
	}

	// Setup request
	sig := cfg.Identity.SignMessage([]byte(cmd.Args.Token +
		strconv.Itoa(int(status)) + cmd.Args.Message))
	sps := &v1.SetProposalStatus{
		Token:               cmd.Args.Token,
		ProposalStatus:      status,
		StatusChangeMessage: cmd.Args.Message,
		Signature:           hex.EncodeToString(sig[:]),
		PublicKey:           hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err = Print(sps, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	spsr, err := c.SetProposalStatus(sps)
	if err != nil {
		return err
	}

	// Print response details
	return Print(spsr, cfg.Verbose, cfg.RawJSON)
}
