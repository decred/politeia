// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/agl/ed25519"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	wwwclient "github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/client"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
	"github.com/decred/politeia/util"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	cfg    *config.Config
	client *wwwclient.Client

	// errUserIdentityNotFound is emitted when a user identity is required
	// but the config object does not contain one.
	errUserIdentityNotFound = errors.New("user identity not found; you must " +
		"either create a new user or use the updateuserkey command to generate " +
		"a new identity for the logged in user")

	// errProposalMDNotFound is emitted when a proposal markdown file is
	// required but has not been passed into the command.
	errProposalMDNotFound = errors.New("proposal markdown file not found; " +
		"you must either provide a markdown file or use the --random flag")

	// errInvalidBeforeAfterUsage is emitted when the command flags 'before'
	// and 'after' are used at the same time.
	errInvalidBeforeAfterUsage = errors.New("the 'before' and 'after' flags " +
		"cannot be used at the same time")

	// errInvoiceCSVNotFound is emitted when a invoice csv file
	// is required but has not been passed into the command.
	errInvoiceCSVNotFound = errors.New("invoice csv file not found.  " +
		"You must either provide a csv file or use the --random flag.")
)

// Cmds is used to represent all of the politeiawwwcli commands.
type Cmds struct {
	AdminInvoices       AdminInvoicesCmd       `command:"admininvoices" description:"(admin) get all invoices (optional by month/year and/or status)"`
	ActiveVotes         ActiveVotesCmd         `command:"activevotes" description:"(public) get the proposals that are being voted on"`
	AuthorizeVote       AuthorizeVoteCmd       `command:"authorizevote" description:"(user)   authorize a proposal vote (must be proposal author)"`
	BatchProposals      BatchProposalsCmd      `command:"batchproposals" description:"(user) retrieve a set of proposals"`
	BatchVoteSummary    BatchVoteSummaryCmd    `command:"batchvotesummary" description:"(user) retrieve the vote summary for a set of proposals"`
	CensorComment       CensorCommentCmd       `command:"censorcomment" description:"(admin)  censor a proposal comment"`
	ChangePassword      ChangePasswordCmd      `command:"changepassword" description:"(user)   change the password for the logged in user"`
	ChangeUsername      ChangeUsernameCmd      `command:"changeusername" description:"(user)   change the username for the logged in user"`
	EditInvoice         EditInvoiceCmd         `command:"editinvoice" description:"(user)    edit a invoice"`
	EditProposal        EditProposalCmd        `command:"editproposal" description:"(user)   edit a proposal"`
	ManageUser          ManageUserCmd          `command:"manageuser" description:"(admin)  edit certain properties of the specified user"`
	EditUser            EditUserCmd            `command:"edituser" description:"(user)   edit the  preferences of the logged in user"`
	GeneratePayouts     GeneratePayoutsCmd     `command:"generatepayouts" description:"(admin) generate a list of payouts with addresses and amounts to pay"`
	Help                HelpCmd                `command:"help" description:"         print a detailed help message for a specific command"`
	InvoiceComments     InvoiceCommentsCmd     `command:"invoicecomments" description:"(user) get the comments for a invoice"`
	InvoiceExchangeRate InvoiceExchangeRateCmd `command:"invoiceexchangerate" description:"(user) get exchange rate for a given month/year"`
	Inventory           InventoryCmd           `command:"inventory" description:"(public) get the proposals that are being voted on"`
	InviteNewUser       InviteNewUserCmd       `command:"invite" description:"(admin)  invite a new user"`
	InvoiceDetails      InvoiceDetailsCmd      `command:"invoicedetails" description:"(public) get the details of a proposal"`
	LikeComment         LikeCommentCmd         `command:"likecomment" description:"(user)   upvote/downvote a comment"`
	LineItemPayouts     LineItemPayoutsCmd     `command:"lineitempayouts" description:"(admin) generate line item list for a given date range"`
	Login               LoginCmd               `command:"login" description:"(public) login to Politeia"`
	Logout              LogoutCmd              `command:"logout" description:"(public) logout of Politeia"`
	Me                  MeCmd                  `command:"me" description:"(user)   get user details for the logged in user"`
	NewInvoice          NewInvoiceCmd          `command:"newinvoice" description:"(user)   create a new invoice"`
	NewProposal         NewProposalCmd         `command:"newproposal" description:"(user)   create a new proposal"`
	NewComment          NewCommentCmd          `command:"newcomment" description:"(user)   create a new proposal comment"`
	NewUser             NewUserCmd             `command:"newuser" description:"(public) create a new user"`
	PayInvoices         PayInvoicesCmd         `command:"payinvoices" description:"(admin) set all approved invoices to paid"`
	Policy              PolicyCmd              `command:"policy" description:"(public) get the server policy"`
	ProposalComments    ProposalCommentsCmd    `command:"proposalcomments" description:"(public) get the comments for a proposal"`
	ProposalDetails     ProposalDetailsCmd     `command:"proposaldetails" description:"(public) get the details of a proposal"`
	ProposalPaywall     ProposalPaywallCmd     `command:"proposalpaywall" description:"(user)   get proposal paywall details for the logged in user"`
	ProposalStats       ProposalStatsCmd       `command:"proposalstats" description:"(public) get statistics on the proposal inventory"`
	UnvettedProposals   UnvettedProposalsCmd   `command:"unvettedproposals" description:"(admin)  get a page of unvetted proposals"`
	VettedProposals     VettedProposalsCmd     `command:"vettedproposals" description:"(public) get a page of vetted proposals"`
	RegisterUser        RegisterUserCmd        `command:"register" description:"(public) register an invited user to cms"`
	RescanUserPayments  RescanUserPaymentsCmd  `command:"rescanuserpayments" description:"(admin)  rescan a user's payments to check for missed payments"`
	ResendVerification  ResendVerificationCmd  `command:"resendverification" description:"(public) resend the user verification email"`
	ResetPassword       ResetPasswordCmd       `command:"resetpassword" description:"(public) reset the password for a user that is not logged in"`
	Secret              SecretCmd              `command:"secret" description:"(user)   ping politeiawww"`
	SendFaucetTx        SendFaucetTxCmd        `command:"sendfaucettx" description:"         send a DCR transaction using the Decred testnet faucet"`
	SetInvoiceStatus    SetInvoiceStatusCmd    `command:"setinvoicestatus" description:"(admin)  set the status of an invoice"`
	SetProposalStatus   SetProposalStatusCmd   `command:"setproposalstatus" description:"(admin)  set the status of a proposal"`
	StartVote           StartVoteCmd           `command:"startvote" description:"(admin)  start the voting period on a proposal"`
	Subscribe           SubscribeCmd           `command:"subscribe" description:"(public) subscribe to all websocket commands and do not exit tool"`
	Tally               TallyCmd               `command:"tally" description:"(public) get the vote tally for a proposal"`
	TestRun             TestRunCmd             `command:"testrun" description:"         run a series of tests on the politeiawww routes (dev use only)"`
	TokenInventory      TokenInventoryCmd      `command:"tokeninventory" description:"(public) get the censorship record tokens of all proposals"`
	UpdateUserKey       UpdateUserKeyCmd       `command:"updateuserkey" description:"(user)   generate a new identity for the logged in user"`
	UserDetails         UserDetailsCmd         `command:"userdetails" description:"(public) get the details of a user profile"`
	UserLikeComments    UserLikeCommentsCmd    `command:"userlikecomments" description:"(user)   get the logged in user's comment upvotes/downvotes for a proposal"`
	UserPendingPayment  UserPendingPaymentCmd  `command:"userpendingpayment" description:"(user)   get details for a pending payment for the logged in user"`
	UserInvoices        UserInvoicesCmd        `command:"userinvoices" description:"(user) get all invoices submitted by a specific user"`
	UserProposals       UserProposalsCmd       `command:"userproposals" description:"(public) get all proposals submitted by a specific user"`
	Users               UsersCmd               `command:"users" description:"(admin)  get a list of users"`
	VerifyUserEmail     VerifyUserEmailCmd     `command:"verifyuseremail" description:"(public) verify a user's email address"`
	VerifyUserPayment   VerifyUserPaymentCmd   `command:"verifyuserpayment" description:"(user)   check if the logged in user has paid their user registration fee"`
	Version             VersionCmd             `command:"version" description:"(public) get server info and CSRF token"`
	Vote                VoteCmd                `command:"vote" description:"(public) cast votes for a proposal"`
	VoteResults         VoteResultsCmd         `command:"voteresults" description:"(public) get vote results for a proposal"`
	VoteStatus          VoteStatusCmd          `command:"votestatus" description:"(public) get the vote status of a proposal"`
	VoteStatuses        VoteStatusesCmd        `command:"votestatuses" description:"(public) get the vote status for all public proposals"`
}

// SetConfig sets the global config variable.
func SetConfig(config *config.Config) {
	cfg = config
}

// SetClient sets the global client variable.
func SetClient(c *wwwclient.Client) {
	client = c
}

// printJSON prints the passed in JSON using the style specified by the global
// config variable.
func printJSON(body interface{}) error {
	switch {
	case cfg.Silent:
		// Keep quiet
	case cfg.Verbose:
		// Verbose printing is handled in the client
	case cfg.RawJSON:
		// Print raw JSON with no formatting
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("Marshal: %v", err)
		}
		fmt.Printf("%v\n", string(b))
	default:
		// Pretty print the body
		b, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			return fmt.Errorf("MarshalIndent: %v", err)
		}
		fmt.Fprintf(os.Stdout, "%s\n", b)
	}

	return nil
}

// promptPassphrase is used to prompt the user for the private passphrase to
// their wallet.
func promptPassphrase() ([]byte, error) {
	prompt := "Enter the private passphrase of your wallet: "
	for {
		fmt.Printf("%v", prompt)
		pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Printf("\n")

		pass = bytes.TrimSpace(pass)
		if len(pass) == 0 {
			continue
		}

		return pass, nil
	}
}

// digestSHA3 returns the hex encoded SHA3-256 of a string.
func digestSHA3(s string) string {
	h := sha3.New256()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// NewIdentity generates a new FullIdentity using randomly generated data to
// create the public/private key pair.
func newIdentity() (*identity.FullIdentity, error) {
	b, err := util.Random(32)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(b)
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}

	id := &identity.FullIdentity{}
	copy(id.Public.Key[:], pub[:])
	copy(id.PrivateKey[:], priv[:])
	return id, nil
}

// merkleRoot converts the passed in list of files into SHA256 digests then
// calculates and returns the merkle root of the digests.
func merkleRoot(files []v1.File) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no proposal files found")
	}

	digests := make([]*[sha256.Size]byte, len(files))
	for i, f := range files {
		// Compute file digest
		b, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return "", fmt.Errorf("decode payload for file %v: %v",
				f.Name, err)
		}
		digest := util.Digest(b)

		// Compare against digest that came with the file
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			return "", fmt.Errorf("invalid digest: file:%v digest:%v",
				f.Name, f.Digest)
		}
		if !bytes.Equal(digest, d[:]) {
			return "", fmt.Errorf("digests do not match for file %v",
				f.Name)
		}

		// Digest is valid
		digests[i] = &d
	}

	// Compute merkle root
	return hex.EncodeToString(merkle.Root(digests)[:]), nil
}

// signedMerkleRoot calculates the merkle root of the passed in list of files,
// signs the merkle root with the passed in identity and returns the signature.
func signedMerkleRoot(files []v1.File, id *identity.FullIdentity) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no proposal files found")
	}
	mr, err := merkleRoot(files)
	if err != nil {
		return "", err
	}
	sig := id.SignMessage([]byte(mr))
	return hex.EncodeToString(sig[:]), nil
}

// verifyProposal verifies a proposal's merkle root, author signature, and
// censorship record.
func verifyProposal(p v1.ProposalRecord, serverPubKey string) error {
	// Verify merkle root
	if len(p.Files) > 0 {
		mr, err := merkleRoot(p.Files)
		if err != nil {
			return err
		}
		if mr != p.CensorshipRecord.Merkle {
			return fmt.Errorf("merkle roots do not match")
		}
	}

	// Verify proposal signature
	pid, err := util.IdentityFromString(p.PublicKey)
	if err != nil {
		return err
	}
	sig, err := util.ConvertSignature(p.Signature)
	if err != nil {
		return err
	}
	if !pid.VerifyMessage([]byte(p.CensorshipRecord.Merkle), sig) {
		return fmt.Errorf("could not verify proposal signature")
	}

	// Verify censorship record signature
	id, err := util.IdentityFromString(serverPubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(p.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	msg := []byte(p.CensorshipRecord.Merkle + p.CensorshipRecord.Token)
	if !id.VerifyMessage(msg, s) {
		return fmt.Errorf("could not verify censorship record signature")
	}

	return nil
}

// verifyInvoice verifies a invoice's merkle root, author signature, and
// censorship record.
func verifyInvoice(p cms.InvoiceRecord, serverPubKey string) error {
	// Verify merkle root
	if len(p.Files) > 0 {
		mr, err := merkleRoot(p.Files)
		if err != nil {
			return err
		}
		if mr != p.CensorshipRecord.Merkle {
			return fmt.Errorf("merkle roots do not match")
		}
	}

	// Verify proposal signature
	pid, err := util.IdentityFromString(p.PublicKey)
	if err != nil {
		return err
	}
	sig, err := util.ConvertSignature(p.Signature)
	if err != nil {
		return err
	}
	if !pid.VerifyMessage([]byte(p.CensorshipRecord.Merkle), sig) {
		return fmt.Errorf("could not verify proposal signature")
	}

	// Verify censorship record signature
	id, err := util.IdentityFromString(serverPubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(p.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	msg := []byte(p.CensorshipRecord.Merkle + p.CensorshipRecord.Token)
	if !id.VerifyMessage(msg, s) {
		return fmt.Errorf("could not verify censorship record signature")
	}

	return nil
}

// convertTicketHashes converts a slice of hexadecimal ticket hashes into
// a slice of byte slices.
func convertTicketHashes(h []string) ([][]byte, error) {
	hashes := make([][]byte, 0, len(h))
	for _, v := range h {
		h, err := chainhash.NewHashFromStr(v)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h[:])
	}
	return hashes, nil
}

// createMDFile returns a File object that was created using a markdown file
// filled with random text.
func createMDFile() (*v1.File, error) {
	var b bytes.Buffer
	b.WriteString("This is the proposal title\n")

	for i := 0; i < 10; i++ {
		r, err := util.Random(32)
		if err != nil {
			return nil, err
		}
		b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")
	}

	return &v1.File{
		Name:    "index.md",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}, nil
}
