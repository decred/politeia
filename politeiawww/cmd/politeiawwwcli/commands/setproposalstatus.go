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
		Status  int    `positional-arg-name:"status" required:"true" description:"Proposal status code"`
		Message string `positional-arg-name:"message" description:"Status change message (required if censoring proposal)"`
	} `positional-args:"true"`
}

func (cmd *SetProposalStatusCmd) Execute(args []string) error {
	token := cmd.Args.Token
	status := cmd.Args.Status

	// Validate user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Setup request
	sig := cfg.Identity.SignMessage([]byte(token + strconv.Itoa(status)))
	sps := &v1.SetProposalStatus{
		Token:               token,
		ProposalStatus:      v1.PropStatusT(status),
		StatusChangeMessage: cmd.Args.Message,
		Signature:           hex.EncodeToString(sig[:]),
		PublicKey:           hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err := Print(sps, cfg.Verbose, cfg.RawJSON)
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
