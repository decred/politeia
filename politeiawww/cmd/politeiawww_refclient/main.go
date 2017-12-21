package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

var (
	host              = flag.String("h", "https://127.0.0.1:4443", "host")
	emailFlag         = flag.String("email", "", "admin email")
	faucetURL         = "https://faucet.decred.org/requestfaucet"
	overridetokenFlag = flag.String("overridetoken", "", "overridetoken for the faucet")
	passwordFlag      = flag.String("password", "", "admin password")
	printJson         = flag.Bool("json", false, "Print JSON")
	test              = flag.String("test", "all", "only run a subset of tests [all,vote]")
)

func firstContact() (*ctx, error) {
	// Always hit / first for csrf token and obtain api version
	fmt.Printf("=== Start ===\n")
	c, err := newClient(true)
	if err != nil {
		return nil, err
	}
	version, err := c.getCSRF()
	if err != nil {
		return nil, err
	}
	fmt.Printf("Version: %v\n", version.Version)
	fmt.Printf("Route  : %v\n", version.Route)
	fmt.Printf("CSRF   : %v\n\n", c.csrf)

	return c, nil
}

func vote() error {
	if *emailFlag == "" {
		return fmt.Errorf("vote tests require admin privileges")
	}
	adminEmail := *emailFlag
	adminPassword := *passwordFlag
	adminID, err := idFromString(adminEmail)
	if err != nil {
		return err
	}

	c, err := firstContact()
	if err != nil {
		return err
	}

	lr, err := c.login(adminEmail, adminPassword)
	if err != nil {
		return err
	}

	// expect admin == true
	if !lr.IsAdmin {
		return fmt.Errorf("expected admin")
	}

	// create new prop
	myprop1, err := c.newProposal(adminID)
	if err != nil {
		return err
	}

	// start voting on prop, wrong state should fail
	//svr, err := c.startVote(adminID, myprop1.CensorshipRecord.Token)
	//if err == nil {
	//	return fmt.Errorf("expected 400, wrong status")
	//}
	//if !strings.HasPrefix(err.Error(), "400") {
	//	return fmt.Errorf("expected 400, wrong status got: %v", err)
	//}

	// move prop to vetted
	psr1, err := c.setPropStatus(adminID,
		myprop1.CensorshipRecord.Token, v1.PropStatusPublic)
	if err != nil {
		return err
	}
	if psr1.ProposalStatus != v1.PropStatusPublic {
		return fmt.Errorf("invalid status got %v wanted %v",
			psr1.ProposalStatus,
			v1.PropStatusPublic)
	}

	// start vote, should succeed
	svr, err := c.startVote(adminID, myprop1.CensorshipRecord.Token)
	if err != nil {
		return err
	}
	spew.Dump(svr)

	return nil
}

func _main() error {
	flag.Parse()

	switch *test {
	case "vote":
		return vote()
	case "all":
		// Fallthrough
	default:
		return fmt.Errorf("invalid test suite: %v", *test)
	}

	c, err := firstContact()
	if err != nil {
		return err
	}

	// Policy
	pr, err := c.policy()
	if err != nil {
		return err
	}

	b, err := util.Random(int(pr.PasswordMinChars))
	if err != nil {
		return err
	}

	email := hex.EncodeToString(b) + "@example.com"
	password := hex.EncodeToString(b)

	// New User
	token, id, paywallAddress, paywallAmount, err := c.newUser(email, password)
	if err != nil {
		return err
	}

	// Verify New User
	sig := id.SignMessage([]byte(token))
	err = c.verifyNewUser(email, token, hex.EncodeToString(sig[:]))
	if err != nil {
		return err
	}

	if paywallAddress != "" && paywallAmount != 0 {
		// Use the testnet faucet to satisfy the user paywall fee.
		faucetTx, err := util.PayWithTestnetFaucet(faucetURL, paywallAddress, paywallAmount,
			*overridetokenFlag)
		if err != nil {
			return fmt.Errorf("unable to pay with %v with %v faucet: %v",
				paywallAddress, paywallAmount, err)
		}

		fmt.Printf("paid %v DCR to %v with faucet tx %v\n",
			paywallAmount, paywallAddress, faucetTx)
	}

	// TODO need to poll for payment confirmation once enforcement is enabled

	// New proposal
	_, err = c.newProposal(id)
	if err == nil {
		return fmt.Errorf("/new should only be accessible by logged in users")
	}
	if !strings.HasPrefix(err.Error(), "403") {
		return fmt.Errorf("newProposal expected 403, got %v", err.Error())
	}

	b, err = util.Random(int(pr.PasswordMinChars))
	if err != nil {
		return err
	}
	newPassword := hex.EncodeToString(b)

	// Reset password
	err = c.resetPassword(email, password, newPassword)
	if err != nil {
		return err
	}

	// Login failure
	_, err = c.login(email, password)
	if err == nil {
		return fmt.Errorf("expected login failure")
	}
	// Login success
	lr, err := c.login(email, newPassword)
	if err != nil {
		return err
	}
	// expect admin == false
	if lr.IsAdmin {
		return fmt.Errorf("expected non admin")
	}

	// Secret
	err = c.secret()
	if err != nil {
		return err
	}

	// Me
	me, err := c.me()
	if err != nil {
		return err
	}
	if me.Email != email {
		return fmt.Errorf("email got %v wanted %v", me.Email, email)
	}
	if me.IsAdmin {
		return fmt.Errorf("IsAdmin got %v wanted %v", me.IsAdmin, false)
	}

	// Change password
	_, err = c.changePassword(newPassword, password)
	if err != nil {
		return err
	}

	// New proposal 1
	myprop1, err := c.newProposal(id)
	if err != nil {
		return err
	}

	// Ensure proposal exists under user
	upr, err := c.proposalsForUser(me.UserID)
	if err != nil {
		return err
	}
	if len(upr.Proposals) != 1 {
		return fmt.Errorf("No proposals returned for user")
	}
	if upr.Proposals[0].CensorshipRecord.Token != myprop1.CensorshipRecord.Token {
		return fmt.Errorf("Proposal tokens don't match")
	}

	// Set new id
	newId, err := idFromString("alt" + email)
	if err != nil {
		return err
	}
	err = c.setNewKey(newId)
	if err != nil {
		return err
	}

	// New proposal 2
	_, err = c.newProposal(id)
	if err == nil {
		return fmt.Errorf("expected error, user identity should be inactive")
	}

	// New proposal 2
	myprop2, err := c.newProposal(newId)
	if err != nil {
		return err
	}

	// Reset old identity
	err = c.setNewKey(id)
	if err != nil {
		return err
	}

	// Get props back out
	pr1, err := c.getProp(myprop1.CensorshipRecord.Token)
	if err != nil {
		return err
	}
	if pr1.Proposal.CensorshipRecord.Token != myprop1.CensorshipRecord.Token {
		return fmt.Errorf("pr1 invalid got %v wanted %v",
			pr1.Proposal.CensorshipRecord.Token,
			myprop1.CensorshipRecord.Token)
	}
	if pr1.Proposal.Status != v1.PropStatusNotReviewed {
		return fmt.Errorf("pr1 invalid status got %v wanted %v",
			pr1.Proposal.Status, v1.PropStatusNotReviewed)
	}
	if len(pr1.Proposal.Files) > 0 {
		return fmt.Errorf("pr1 unexpected proposal data received")
	}

	pr2, err := c.getProp(myprop2.CensorshipRecord.Token)
	if err != nil {
		return err
	}
	if pr2.Proposal.CensorshipRecord.Token != myprop2.CensorshipRecord.Token {
		return fmt.Errorf("pr2 invalid got %v wanted %v",
			pr2.Proposal.CensorshipRecord.Token,
			myprop2.CensorshipRecord.Token)
	}
	if pr2.Proposal.Status != v1.PropStatusNotReviewed {
		return fmt.Errorf("pr2 invalid status got %v wanted %v",
			pr2.Proposal.Status, v1.PropStatusNotReviewed)
	}

	// Create enough proposals to have 2 pages
	for i := 0; i < int(pr.ProposalListPageSize); i++ {
		_, err = c.newProposal(id)
		if err != nil {
			return err
		}
	}

	_, err = c.allUnvetted("")
	if err == nil {
		return fmt.Errorf("/unvetted should only be accessible by admin users")
	}

	// Vetted proposals
	err = c.allVetted()
	if err != nil {
		return err
	}

	// Logout
	err = c.logout()
	if err != nil {
		return err
	}

	// Execute routes with admin permissions if the flags are set
	if *emailFlag != "" {
		adminEmail := *emailFlag
		adminPassword := *passwordFlag
		adminID, err := idFromString(adminEmail)
		if err != nil {
			return err
		}

		c, err = newClient(true)
		if err != nil {
			return err
		}
		_, err = c.getCSRF()
		if err != nil {
			return err
		}

		lr, err = c.login(adminEmail, adminPassword)
		if err != nil {
			return err
		}

		// expect admin == true
		if !lr.IsAdmin {
			return fmt.Errorf("expected admin")
		}

		// Me admin
		me, err := c.me()
		if err != nil {
			return err
		}
		if me.Email != adminEmail {
			return fmt.Errorf("admin email got %v wanted %v",
				me.Email, adminEmail)
		}
		if !me.IsAdmin {
			return fmt.Errorf("IsAdmin got %v wanted %v",
				me.IsAdmin, true)
		}

		// Test unvetted paging
		unvettedPage1, err := c.allUnvetted("")
		if err != nil {
			return err
		}
		lastProposal := unvettedPage1.Proposals[len(unvettedPage1.Proposals)-1]
		unvettedPage2, err := c.allUnvetted(lastProposal.CensorshipRecord.Token)
		if err != nil {
			return err
		}
		if len(unvettedPage2.Proposals) == 0 {
			return fmt.Errorf("empty 2nd page of unvetted proposals")
		}

		// Create test proposal 1
		pr1, err := c.getProp(myprop1.CensorshipRecord.Token)
		if err != nil {
			return err
		}
		if len(pr1.Proposal.Files) == 0 {
			return fmt.Errorf("pr1 expected proposal data")
		}

		// Move first proposal to published
		psr1, err := c.setPropStatus(adminID,
			myprop1.CensorshipRecord.Token, v1.PropStatusPublic)
		if err != nil {
			return err
		}
		if psr1.ProposalStatus != v1.PropStatusPublic {
			return fmt.Errorf("invalid status got %v wanted %v",
				psr1.ProposalStatus,
				v1.PropStatusPublic)
		}

		// Move second proposal to censored
		psr2, err := c.setPropStatus(adminID,
			myprop2.CensorshipRecord.Token, v1.PropStatusCensored)
		if err != nil {
			return err
		}
		if psr2.ProposalStatus != v1.PropStatusCensored {
			return fmt.Errorf("invalid status got %v wanted %v",
				psr2.ProposalStatus,
				v1.PropStatusCensored)
		}

		// Get props back out and check status
		_pr1, err := c.getProp(myprop1.CensorshipRecord.Token)
		if err != nil {
			return err
		}
		if _pr1.Proposal.CensorshipRecord.Token !=
			myprop1.CensorshipRecord.Token {
			return fmt.Errorf("_pr1 invalid got %v wanted %v",
				_pr1.Proposal.CensorshipRecord.Token,
				myprop1.CensorshipRecord.Token)
		}
		if _pr1.Proposal.Status != v1.PropStatusPublic {
			return fmt.Errorf("_pr1 invalid status got %v wanted %v",
				_pr1.Proposal.Status, v1.PropStatusPublic)
		}

		_pr2, err := c.getProp(myprop2.CensorshipRecord.Token)
		if err != nil {
			return err
		}
		if _pr2.Proposal.CensorshipRecord.Token !=
			myprop2.CensorshipRecord.Token {
			return fmt.Errorf("_pr2 invalid got %v wanted %v",
				_pr2.Proposal.CensorshipRecord.Token,
				myprop2.CensorshipRecord.Token)
		}
		if _pr2.Proposal.Status != v1.PropStatusCensored {
			return fmt.Errorf("_pr2 invalid status got %v wanted %v",
				_pr2.Proposal.Status, v1.PropStatusCensored)
		}

		// Comment on proposals without a parent
		cr, err := c.comment(adminID, myprop1.CensorshipRecord.Token,
			"I like this prop", "")
		if err != nil {
			return err
		}
		// Comment on original comment
		cr, err = c.comment(adminID, myprop1.CensorshipRecord.Token,
			"you are right!", cr.CommentID)
		if err != nil {
			return err
		}
		// Comment on comment
		cr, err = c.comment(adminID, myprop1.CensorshipRecord.Token,
			"you are wrong!", cr.CommentID)
		if err != nil {
			return err
		}

		// Comment on proposals without a parent
		cr2, err := c.comment(adminID, myprop1.CensorshipRecord.Token,
			"I dont like this prop", "")
		if err != nil {
			return err
		}
		// Comment on original comment
		cr, err = c.comment(adminID, myprop1.CensorshipRecord.Token,
			"you are right!", cr2.CommentID)
		if err != nil {
			return err
		}
		// Comment on original comment
		cr, err = c.comment(adminID, myprop1.CensorshipRecord.Token,
			"you are crazy!", cr2.CommentID)
		if err != nil {
			return err
		}

		// Get comments
		gcr, err := c.commentGet(myprop1.CensorshipRecord.Token)
		if err != nil {
			return err
		}
		// Expect 6 comments
		if len(gcr.Comments) != 6 {
			return fmt.Errorf("expected 6 comments, got %v",
				len(gcr.Comments))
		}
		// Get prop out again and check comments num
		_pr1, err = c.getProp(myprop1.CensorshipRecord.Token)
		if err != nil {
			return err
		}
		if _pr1.Proposal.NumComments != uint(len(gcr.Comments)) {
			return fmt.Errorf("expected %v comments, got %v",
				len(gcr.Comments), _pr1.Proposal.NumComments)
		}

		gcr2, err := c.commentGet(myprop2.CensorshipRecord.Token)
		if err != nil {
			return err
		}
		// Expect nothing
		if len(gcr2.Comments) != 0 {
			return fmt.Errorf("expected 0 comments, got %v",
				len(gcr2.Comments))
		}
		// Get prop out again and check comments num
		_pr2, err = c.getProp(myprop2.CensorshipRecord.Token)
		if err != nil {
			return err
		}
		if _pr2.Proposal.NumComments != uint(len(gcr2.Comments)) {
			return fmt.Errorf("expected %v comments, got %v",
				len(gcr2.Comments), _pr2.Proposal.NumComments)
		}

		// Logout
		err = c.logout()
		if err != nil {
			return err
		}
	}

	// Assets
	// XXX disabled until fixed
	//err = c.assets()
	//if err != nil {
	//	return err
	//}

	// Secret once more that should fail
	err = c.secret()
	if err == nil {
		return fmt.Errorf("secret should have failed")
	}
	if !strings.HasPrefix(err.Error(), "403") {
		return fmt.Errorf("secret expected 403")
	}

	// Me
	_, err = c.me()
	if err == nil {
		return fmt.Errorf("me should have failed")
	}
	if !strings.HasPrefix(err.Error(), "403") {
		return fmt.Errorf("me expected 403")
	}

	fmt.Printf("refclient run successful\n")
	fmt.Printf("=== End ===\n")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
