// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

// NewDCCCmd submits a new dcc.
type NewDCCCmd struct {
	Args struct {
		Type        uint     `positional-arg-name:"type"`            // 1 for Issuance, 2 for Revocation
		Attachments []string `positional-arg-name:"attachmentfiles"` // DCC attachment files
	} `positional-args:"true" optional:"true"`
	Type          string ``
	NomineeUserID string `long:"nomineeuserid" optional:"true" description:"The UserID of the Nominated User"`
	Statement     string `long:"statement" optional:"true" description:"Statement in support of the DCC"`
	Domain        string `long:"domain" optional:"true" description:"The domain of the nominated user"`
}

// Execute executes the new dcc command.
func (cmd *NewDCCCmd) Execute(args []string) error {

	// Check for a valid DCC type
	if int(cmd.Args.Type) <= 0 || int(cmd.Args.Type) > 2 {
		return errInvalidDCCType
	}

	// Check for user identity
	if cfg.Identity == nil {
		return errUserIdentityNotFound
	}

	// Get server public key
	vr, err := client.Version()
	if err != nil {
		return err
	}
	var domainType int
	if cmd.Statement == "" || cmd.NomineeUserID == "" || cmd.Domain == "" {
		reader := bufio.NewReader(os.Stdin)
		if cmd.Statement == "" {
			fmt.Print("Enter your statement to support the DCC: ")
			cmd.Statement, _ = reader.ReadString('\n')
		}
		if cmd.NomineeUserID == "" {
			fmt.Print("Enter the nominee user id: ")
			cmd.NomineeUserID, _ = reader.ReadString('\n')
		}
		if cmd.Domain == "" {
			for {
				fmt.Printf("Domain Type: (1) Developer, (2) Marketing, (3) " +
					"Community, (4) Research, (5) Design, (6) Documentation:  ")
				cmd.Domain, _ = reader.ReadString('\n')
				domainType, err = strconv.Atoi(strings.TrimSpace(cmd.Domain))
				if err != nil {
					fmt.Println("Invalid entry, please try again.")
					continue
				}
				if domainType < 1 || domainType > 6 {
					fmt.Println("Invalid domain type entered, please try again.")
					continue
				}
				str := fmt.Sprintf(
					"Your current Domain setting is: \"%v\" Keep this?",
					domainType)
				update, err := promptListBool(reader, str, "yes")
				if err != nil {
					return err
				}
				if update {
					break
				}
			}
		}
		fmt.Print("\nPlease carefully review your information and ensure it's " +
			"correct. If not, press Ctrl + C to exit. Or, press Enter to continue.")
		reader.ReadString('\n')
	}

	dccInput := &cms.DCCInput{}
	dccInput.SponsorStatement = strings.TrimSpace(cmd.Statement)
	dccInput.NomineeUserID = strings.TrimSpace(cmd.NomineeUserID)
	dccInput.Type = cms.DCCTypeT(int(cmd.Args.Type))
	dccInput.Domain = cms.DomainTypeT(domainType)

	// Print request details
	err = printJSON(dccInput)
	if err != nil {
		return err
	}
	b, err := json.Marshal(dccInput)
	if err != nil {
		return fmt.Errorf("Marshal: %v", err)
	}

	f := www.File{
		Name:    "dcc.json",
		MIME:    mime.DetectMimeType(b),
		Digest:  hex.EncodeToString(util.Digest(b)),
		Payload: base64.StdEncoding.EncodeToString(b),
	}

	files := make([]www.File, 0, www.PolicyMaxImages+1)
	files = append(files, f)

	attachmentFiles := cmd.Args.Attachments
	// Read attachment files into memory and convert to type File
	for _, file := range attachmentFiles {
		path := util.CleanAndExpandPath(file)
		attachment, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", path, err)
		}

		f := www.File{
			Name:    filepath.Base(file),
			MIME:    mime.DetectMimeType(attachment),
			Digest:  hex.EncodeToString(util.Digest(attachment)),
			Payload: base64.StdEncoding.EncodeToString(attachment),
		}

		files = append(files, f)
	}

	// Compute merkle root and sign it
	sig, err := signedMerkleRoot(files, cfg.Identity)
	if err != nil {
		return fmt.Errorf("SignMerkleRoot: %v", err)
	}

	// Setup new dcc request
	nd := cms.NewDCC{
		Files:     files,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}

	// Print request details
	err = printJSON(nd)
	if err != nil {
		return err
	}

	// Send request
	ndr, err := client.NewDCC(nd)
	if err != nil {
		return err
	}

	// Verify the censorship record
	pr := www.ProposalRecord{
		Files:            nd.Files,
		PublicKey:        nd.PublicKey,
		Signature:        nd.Signature,
		CensorshipRecord: ndr.CensorshipRecord,
	}
	err = verifyProposal(pr, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify proposal %v: %v",
			pr.CensorshipRecord.Token, err)
	}

	// Print response details
	return printJSON(ndr)
}
