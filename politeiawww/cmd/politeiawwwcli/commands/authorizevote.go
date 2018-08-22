package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

type AuthorizeVoteCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" description:"Proposal censorship token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *AuthorizeVoteCmd) Execute(args []string) error {
	token := cmd.Args.Token

	// Check for user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Get server public key
	vr, err := c.Version()
	if err != nil {
		return err
	}

	// Get proposal version
	pdr, err := c.ProposalDetails(token)
	if err != nil {
		return err
	}

	// Setup authorize vote request
	sig := cfg.Identity.SignMessage([]byte(token + pdr.Proposal.Version))
	av := &v1.AuthorizeVote{
		Token:     token,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Print request details
	err = Print(av, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	avr, err := c.AuthorizeVote(av)
	if err != nil {
		return err
	}

	// Validate authorize vote receipt
	serverID, err := util.IdentityFromString(vr.PubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(avr.Receipt)
	if err != nil {
		return err
	}
	if !serverID.VerifyMessage([]byte(av.Signature), s) {
		return fmt.Errorf("could not verify authorize vote receipt")
	}

	// Print response details
	return Print(avr, cfg.Verbose, cfg.RawJSON)
}
