package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"

	"golang.org/x/net/publicsuffix"

	"github.com/agl/ed25519"
	"github.com/decred/politeia/politeiad/api/v1/identity"
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
)

type ctx struct {
	client *http.Client
	csrf   string
}

func newClient(skipVerify bool) (*ctx, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}
	return &ctx{
		client: &http.Client{
			Transport: tr,
			Jar:       jar,
		}}, nil
}

func (c *ctx) makeRequest(method string, route string, b interface{}) ([]byte, error) {
	var requestBody []byte
	if b != nil {
		var err error
		requestBody, err = json.Marshal(b)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := *host + v1.PoliteiaWWWAPIRoute + route
	fmt.Printf("Request: %v %v\n", method, v1.PoliteiaWWWAPIRoute+route)

	if *printJson {
		fmt.Println("  " + string(requestBody))
	}

	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.Header.Add(v1.CsrfToken, c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	if *printJson {
		fmt.Printf("Response: %v %v\n\n", r.StatusCode, string(responseBody))
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	return responseBody, nil
}

func (c *ctx) getCSRF() (*v1.VersionReply, error) {
	requestBody, err := json.Marshal(v1.Version{})
	if err != nil {
		return nil, err
	}

	fmt.Printf("Request: GET /\n")

	if *printJson {
		fmt.Println("  " + string(requestBody))
	}

	req, err := http.NewRequest(http.MethodGet, *host, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	r, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	if *printJson {
		fmt.Println("Response: " + string(responseBody) + "\n")
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	var v v1.VersionReply
	err = json.Unmarshal(responseBody, &v)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal version: %v", err)
	}

	c.csrf = r.Header.Get(v1.CsrfToken)

	return &v, nil
}

func (c *ctx) policy() (*v1.PolicyReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RoutePolicy, v1.Policy{})
	if err != nil {
		return nil, err
	}

	var pr v1.PolicyReply
	err = json.Unmarshal(responseBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal PolicyReply: %v",
			err)
	}

	return &pr, nil
}

func idFromEmail(email string) (*identity.FullIdentity, error) {
	// super hack alert, we are going to use the email address as the
	// privkey.  We do this in order to sign things as an admin later.
	buf := [32]byte{}
	copy(buf[:], []byte(email))
	r := bytes.NewReader(buf[:])
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	id := &identity.FullIdentity{}
	copy(id.Public.Key[:], pub[:])
	copy(id.PrivateKey[:], priv[:])
	return id, nil
}

func (c *ctx) newUser(email string, password string) (string, *identity.FullIdentity, string, float64, error) {
	id, err := idFromEmail(email)
	if err != nil {
		return "", nil, "", 0, err
	}
	u := v1.NewUser{
		Email:     email,
		Password:  password,
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	responseBody, err := c.makeRequest("POST", v1.RouteNewUser, u)
	if err != nil {
		return "", nil, "", 0, err
	}

	var nur v1.NewUserReply
	err = json.Unmarshal(responseBody, &nur)
	if err != nil {
		return "", nil, "", 0,
			fmt.Errorf("Could not unmarshal NewUserReply: %v", err)
	}

	//fmt.Printf("Verification Token: %v\n", nur.VerificationToken)
	return nur.VerificationToken, id, nur.PaywallAddress, nur.PaywallAmount, nil
}

func (c *ctx) verifyNewUser(email, token, sig string) error {
	_, err := c.makeRequest("GET", "/user/verify/?email="+email+
		"&verificationtoken="+token+"&signature="+sig, nil)
	return err
}

func (c *ctx) login(email, password string) (*v1.LoginReply, error) {
	l := v1.Login{
		Email:    email,
		Password: password,
	}

	responseBody, err := c.makeRequest("POST", v1.RouteLogin, l)
	if err != nil {
		return nil, err
	}

	var lr v1.LoginReply
	err = json.Unmarshal(responseBody, &lr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal LoginReply: %v",
			err)
	}

	return &lr, nil
}

func (c *ctx) secret() error {
	l := v1.Login{}
	_, err := c.makeRequest("POST", v1.RouteSecret, l)
	return err
}

func (c *ctx) comment(id *identity.FullIdentity, token, comment, parentID string) (*v1.NewCommentReply, error) {
	cm := v1.NewComment{
		Token:    token,
		ParentID: parentID,
		Comment:  comment,
	}
	// Sign token+parentid+comment
	msg := []byte(cm.Token + cm.ParentID + cm.Comment)
	sig := id.SignMessage(msg)
	cm.Signature = hex.EncodeToString(sig[:])

	responseBody, err := c.makeRequest("POST", v1.RouteNewComment, cm)
	if err != nil {
		return nil, err
	}

	var cr v1.NewCommentReply
	err = json.Unmarshal(responseBody, &cr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal CommentReply: %v",
			err)
	}

	return &cr, nil
}

func (c *ctx) commentGet(token string) (*v1.GetCommentsReply, error) {
	responseBody, err := c.makeRequest("GET", "/proposals/"+token+
		"/comments", v1.GetComments{})
	if err != nil {
		return nil, err
	}

	var gcr v1.GetCommentsReply
	err = json.Unmarshal(responseBody, &gcr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal GetCommentReply: %v",
			err)
	}

	return &gcr, nil
}

func (c *ctx) me() (*v1.MeReply, error) {
	l := v1.Me{}

	responseBody, err := c.makeRequest("GET", v1.RouteUserMe, l)
	if err != nil {
		return nil, err
	}

	var mr v1.MeReply
	err = json.Unmarshal(responseBody, &mr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal MeReply: %v",
			err)
	}

	return &mr, nil
}

func (c *ctx) newProposal(id *identity.FullIdentity) (*v1.NewProposalReply, error) {
	payload := []byte("This is a description")
	h := sha256.New()
	h.Write(payload)

	sig := id.SignMessage([]byte(hex.EncodeToString(h.Sum(nil))))
	np := v1.NewProposal{
		Files: make([]v1.File, 0),
		// We can get away with just signing the digest because there
		// is only one file.
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	np.Files = append(np.Files, v1.File{
		Name:    "index.md",
		MIME:    "text/plain; charset=utf-8",
		Digest:  hex.EncodeToString(h.Sum(nil)),
		Payload: base64.StdEncoding.EncodeToString(payload),
	})

	responseBody, err := c.makeRequest("POST", v1.RouteNewProposal, np)
	if err != nil {
		return nil, err
	}

	var vr v1.NewProposalReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return nil,
			fmt.Errorf("Could not unmarshal NewProposalReply: %v",
				err)
	}

	return &vr, nil
}

func (c *ctx) allVetted() error {
	responseBody, err := c.makeRequest("GET", v1.RouteAllVetted,
		v1.GetAllVetted{})
	if err != nil {
		return err
	}

	var vr v1.GetAllVettedReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal GetAllVettedReply: %v",
			err)
	}

	return nil
}

func (c *ctx) allUnvetted(after string) (*v1.GetAllUnvettedReply, error) {
	u := v1.GetAllUnvetted{
		After: after,
	}
	responseBody, err := c.makeRequest("GET", v1.RouteAllUnvetted, u)
	if err != nil {
		return nil, err
	}

	var ur v1.GetAllUnvettedReply
	err = json.Unmarshal(responseBody, &ur)
	if err != nil {
		return nil,
			fmt.Errorf("Could not unmarshal GetAllUnvettedReply: %v",
				err)
	}

	return &ur, nil
}

func (c *ctx) getProp(token string) (*v1.ProposalDetailsReply, error) {
	responseBody, err := c.makeRequest("GET", "/proposals/"+token,
		v1.ProposalsDetails{})
	if err != nil {
		return nil, err
	}

	var pr v1.ProposalDetailsReply
	err = json.Unmarshal(responseBody, &pr)
	if err != nil {
		return nil,
			fmt.Errorf("Could not unmarshal GetProposalReply: %v",
				err)
	}

	return &pr, nil
}

func (c *ctx) setPropStatus(id *identity.FullIdentity, token string, status v1.PropStatusT) (*v1.SetProposalStatusReply, error) {
	ps := v1.SetProposalStatus{
		Token:          token,
		ProposalStatus: status,
	}
	// Sign token+string(status)
	msg := []byte(ps.Token +
		strconv.FormatUint(uint64(ps.ProposalStatus), 10))
	var err error
	sig := id.SignMessage(msg)
	ps.Signature = hex.EncodeToString(sig[:])

	responseBody, err := c.makeRequest("POST",
		"/proposals/"+token+"/status", /*v1.RouteSetProposalStatus*/
		ps)
	if err != nil {
		return nil, err
	}

	var psr v1.SetProposalStatusReply
	err = json.Unmarshal(responseBody, &psr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"SetProposalStatusReply: %v", err)
	}

	return &psr, nil
}

func (c *ctx) changePassword(currentPassword, newPassword string) (*v1.ChangePasswordReply, error) {
	cp := v1.ChangePassword{
		CurrentPassword: currentPassword,
		NewPassword:     newPassword,
	}
	responseBody, err := c.makeRequest("POST", v1.RouteChangePassword, cp)
	if err != nil {
		return nil, err
	}

	var cpr v1.ChangePasswordReply
	err = json.Unmarshal(responseBody, &cpr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"ChangePasswordReply: %v", err)
	}

	return &cpr, nil
}

func (c *ctx) resetPassword(email, password, newPassword string) error {
	rp := v1.ResetPassword{
		Email: email,
	}
	responseBody, err := c.makeRequest("POST", v1.RouteResetPassword, rp)
	if err != nil {
		return err
	}

	var rpr v1.ResetPasswordReply
	err = json.Unmarshal(responseBody, &rpr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal ResetPasswordReply: %v", err)
	}

	rp.NewPassword = newPassword
	rp.VerificationToken = rpr.VerificationToken

	responseBody, err = c.makeRequest("POST", v1.RouteResetPassword, rp)
	if err != nil {
		return err
	}

	err = json.Unmarshal(responseBody, &rpr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal ResetPasswordReply: %v", err)
	}

	return nil
}

func (c *ctx) logout() error {
	l := v1.Logout{}
	_, err := c.makeRequest("GET", v1.RouteLogout, l)
	return err
}

func (c *ctx) assets() error {
	route := *host + "/static/" //v1.PoliteiaWWWAPIRoute + v1.RouteSecret
	fmt.Printf("asset Route : %v\n", route)
	req, err := http.NewRequest("GET", route, nil)
	if err != nil {
		return err
	}
	req.Header.Add(v1.CsrfToken, c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		r.Body.Close()
	}()

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	_, err = io.Copy(os.Stdout, r.Body)
	return err
}

func _main() error {
	flag.Parse()

	// Always hit / first for csrf token and obtain api version
	fmt.Printf("=== Start ===\n")
	c, err := newClient(true)
	if err != nil {
		return err
	}
	version, err := c.getCSRF()
	if err != nil {
		return err
	}
	fmt.Printf("Version: %v\n", version.Version)
	fmt.Printf("Route  : %v\n", version.Route)
	fmt.Printf("CSRF   : %v\n\n", c.csrf)

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

	// Use the testnet faucet to satisfy the user paywall fee.
	faucetTx, err := util.PayWithTestnetFaucet(faucetURL, paywallAddress, paywallAmount,
		*overridetokenFlag)
	if err != nil {
		return fmt.Errorf("unable to pay with %v with %v faucet: %v",
			paywallAddress, paywallAmount, err)
	}

	fmt.Printf("paid %v DCR to %v with faucet tx %v\n",
		paywallAmount, paywallAddress, faucetTx)

	// TODO need to poll for payment confirmation once enforcement is enabled

	// New proposal
	_, err = c.newProposal(id)
	if err == nil {
		return fmt.Errorf("/new should only be accessible by logged in users")
	}
	if err.Error() != "403" {
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

	// New proposal 2
	myprop2, err := c.newProposal(id)
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
	if len(pr1.Proposal.Files) > 0 || len(pr1.Proposal.Name) > 0 {
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
		adminID, err := idFromEmail(adminEmail)
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

		gcr2, err := c.commentGet(myprop2.CensorshipRecord.Token)
		if err != nil {
			return err
		}
		// Expect nothing
		if len(gcr2.Comments) != 0 {
			return fmt.Errorf("expected 0 comments, got %v",
				len(gcr2.Comments))
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
	if err.Error() != "403" {
		return fmt.Errorf("secret expected 403")
	}

	// Me
	_, err = c.me()
	if err == nil {
		return fmt.Errorf("me should have failed")
	}
	if err.Error() != "403" {
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
