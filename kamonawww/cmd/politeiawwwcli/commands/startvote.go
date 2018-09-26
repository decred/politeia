package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

type StartVoteCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *StartVoteCmd) Execute(args []string) error {
	token := cmd.Args.Token

	// Check for user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Setup start vote request
	sig := cfg.Identity.SignMessage([]byte(token))
	sv := &v1.StartVote{
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Vote: v1.Vote{
			Token:    token,
			Mask:     0x03, // bit 0 no, bit 1 yes
			Duration: 2016,
			Options: []v1.VoteOption{
				{
					Id:          "no",
					Description: "Don't approve proposal",
					Bits:        0x01,
				},
				{
					Id:          "yes",
					Description: "Approve proposal",
					Bits:        0x02,
				},
			},
		},
	}

	// Print request details
	err := Print(sv, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	svr, err := c.StartVote(sv)
	if err != nil {
		return err
	}

	// Print response details.  Remove eligible tickets from
	// StartVoteReply so that the output is legible.
	svr.EligibleTickets = []string{"removed by politeiawwwcli for readability"}
	return Print(svr, cfg.Verbose, cfg.RawJSON)
}
