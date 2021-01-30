// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// voteStartCmd starts the voting period on the specified proposal.
type voteStartCmd struct {
	Args struct {
		Token            string `positional-arg-name:"token" required:"true"`
		Duration         uint32 `positional-arg-name:"duration"`
		QuorumPercentage uint32 `positional-arg-name:"quorumpercentage"`
		PassPercentage   uint32 `positional-arg-name:"passpercentage"`
	} `positional-args:"true"`
}

/*
// Execute executes the voteStartCmd command.
//
// This function satisfies the go-flags Commander interface.
func (cmd *voteStartCmd) Execute(args []string) error {
	token := cmd.Args.Token

	// Verify user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Get proposal version
	pr, err := proposalRecordLatest(pi.PropStateVetted, token)
	if err != nil {
		return fmt.Errorf("proposalRecordLatest: %v", err)
	}
	version, err := strconv.ParseUint(pr.Version, 10, 32)
	if err != nil {
		return err
	}

	// Setup vote params
	var (
		// Default values
		duration uint32 = 2016
		quorum   uint32 = 20
		pass     uint32 = 60
	)
	if cmd.Args.Duration != 0 {
		duration = cmd.Args.Duration
	}
	if cmd.Args.QuorumPercentage != 0 {
		quorum = cmd.Args.QuorumPercentage
	}
	if cmd.Args.PassPercentage != 0 {
		pass = cmd.Args.PassPercentage
	}

	// Setup request
	vote := pi.VoteParams{
		Token:            token,
		Version:          uint32(version),
		Type:             pi.VoteTypeStandard,
		Mask:             0x03,
		Duration:         duration,
		QuorumPercentage: quorum,
		PassPercentage:   pass,
		Options: []pi.VoteOption{
			{
				ID:          pi.VoteOptionIDApprove,
				Description: "Approve proposal",
				Bit:         0x01,
			},
			{
				ID:          pi.VoteOptionIDReject,
				Description: "Don't approve proposal",
				Bit:         0x02,
			},
		},
	}
	vb, err := json.Marshal(vote)
	if err != nil {
		return err
	}
	msg := hex.EncodeToString(util.Digest(vb))
	b := cfg.Identity.SignMessage([]byte(msg))
	signature := hex.EncodeToString(b[:])
	vs := pi.VoteStart{
		Starts: []pi.StartDetails{
			{
				Params:    vote,
				PublicKey: cfg.Identity.Public.String(),
				Signature: signature,
			},
		},
	}

	// Send request. The request and response details are printed to
	// the console.
	err = shared.PrintJSON(vs)
	if err != nil {
		return err
	}
	vsr, err := client.VoteStart(vs)
	if err != nil {
		return err
	}
	vsr.EligibleTickets = []string{"removed by piwww for readability"}
	err = shared.PrintJSON(vsr)
	if err != nil {
		return err
	}

	return nil
}
*/

// voteStartHelpMsg is the help command message.
var voteStartHelpMsg = `votestart <token> <duration> <quorumpercentage> <passpercentage>

Start the voting period for a proposal. Requires admin privileges.

Arguments:
1. token             (string, required)  Proposal censorship token
2. duration          (uint32, optional)  Duration of vote in blocks
                                         (default: 2016)
3. quorumpercentage  (uint32, optional)  Percent of total votes required to
                                         reach a quorum (default: 10)
4. passpercentage    (uint32, optional)  Percent of cast votes required for
                                         vote to be approved (default: 60)
`
