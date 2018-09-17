package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
	"github.com/decred/politeia/util"
)

type AuthorizeVoteCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" description:"Proposal censorship token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *AuthorizeVoteCmd) Execute(args []string) error {
	token := cmd.Args.Token

	// Load identity
	if config.UserIdentity == nil {
		return fmt.Errorf(config.ErrorNoUserIdentity)
	}
	id := config.UserIdentity

	// Get server public key
	vr, err := Ctx.Version()
	if err != nil {
		return err
	}

	// Get proposal version
	pdr, err := Ctx.GetProp(token, vr.PubKey)
	if err != nil {
		return err
	}

	// Create authorize vote signature
	sigB := id.SignMessage([]byte(token + pdr.Proposal.Version))
	sig := hex.EncodeToString(sigB[:])
	publicKey := hex.EncodeToString(id.Public.Key[:])

	// Authorize vote
	avr, err := Ctx.AuthorizeVote(token, publicKey, sig)
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
	if !serverID.VerifyMessage([]byte(sig), s) {
		return fmt.Errorf("could not verify authorize vote receipt")
	}

	return nil
}
