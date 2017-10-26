package main

import (
	"bytes"
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

	"golang.org/x/net/publicsuffix"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

var (
	host         = flag.String("h", "https://127.0.0.1:4443", "host")
	emailFlag    = flag.String("email", "", "admin email")
	passwordFlag = flag.String("password", "", "admin password")
	printJson    = flag.Bool("json", false, "Print JSON")
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
	return &ctx{client: &http.Client{
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
		fmt.Println("Response: " + string(responseBody) + "\n")
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

func (c *ctx) newUser(email, password string) (string, error) {
	u := v1.NewUser{
		Email:    email,
		Password: password,
	}

	responseBody, err := c.makeRequest("POST", v1.RouteNewUser, u)
	if err != nil {
		return "", err
	}

	var nur v1.NewUserReply
	err = json.Unmarshal(responseBody, &nur)
	if err != nil {
		return "", fmt.Errorf("Could not unmarshal NewUserReply: %v",
			err)
	}

	//fmt.Printf("Verification Token: %v\n", nur.VerificationToken)
	return nur.VerificationToken, nil
}

func (c *ctx) verifyNewUser(email, token string) error {
	_, err := c.makeRequest("GET", "/user/verify/?email="+email+
		"&verificationtoken="+token, nil)
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

func (c *ctx) newProposal() (*v1.NewProposalReply, error) {
	np := v1.NewProposal{
		Name:  "test",
		Files: make([]v1.File, 0),
	}

	np.Files = append(np.Files, v1.File{
		Name:    "index.md",
		MIME:    "text/plain; charset=utf-8",
		Payload: base64.StdEncoding.EncodeToString([]byte("This is a description")),
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

func (c *ctx) allUnvetted() (*v1.GetAllUnvettedReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteAllUnvetted,
		v1.GetAllUnvetted{})
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

func (c *ctx) setPropStatus(token string, status v1.PropStatusT) (*v1.SetProposalStatusReply, error) {
	ps := v1.SetProposalStatus{
		Token:          token,
		ProposalStatus: status,
	}
	responseBody, err := c.makeRequest("POST",
		"/proposals/"+token+"/setstatus", /*v1.RouteSetProposalStatus*/
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
	token, err := c.newUser(email, password)
	if err != nil {
		return err
	}

	// Verify New User
	err = c.verifyNewUser(email, token)
	if err != nil {
		// ugly hack that ignores special redirect handling in verify
		// user.  We assume we were redirected to the correct page and
		// end up 404 because we don't route the success/failure page.
		if err.Error() != "404" {
			return err
		}
	}

	// New proposal
	_, err = c.newProposal()
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
	password = newPassword

	// Login
	lr, err := c.login(email, password)
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
	b, err = util.Random(8)
	if err != nil {
		return err
	}
	newPassword = hex.EncodeToString(b)
	cpr, err := c.changePassword(password, newPassword)
	if err != nil {
		return err
	}
	if cpr.ErrorCode != v1.StatusSuccess {
		return fmt.Errorf("changePassword failed with errorcode %v", cpr.ErrorCode)
	}

	// New proposal 1
	myprop1, err := c.newProposal()
	if err != nil {
		return err
	}

	// New proposal 2
	myprop2, err := c.newProposal()
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

	_, err = c.allUnvetted()
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

		unvetted, err := c.allUnvetted()
		// Expect no error
		if err != nil {
			return err
		}

		// XXX verify response
		_ = unvetted

		pr1, err := c.getProp(myprop1.CensorshipRecord.Token)
		if err != nil {
			return err
		}
		if len(pr1.Proposal.Files) == 0 {
			return fmt.Errorf("pr1 expected proposal data")
		}

		// Move first proposal to published
		psr1, err := c.setPropStatus(myprop1.CensorshipRecord.Token,
			v1.PropStatusPublic)
		if err != nil {
			return err
		}
		if psr1.ProposalStatus != v1.PropStatusPublic {
			return fmt.Errorf("invalid status got %v wanted %v",
				psr1.ProposalStatus,
				v1.PropStatusPublic)
		}

		// Move second proposal to censored
		psr2, err := c.setPropStatus(myprop2.CensorshipRecord.Token,
			v1.PropStatusCensored)
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
	fmt.Printf("secret expected error: %v\n", err)

	// Me
	_, err = c.me()
	if err == nil {
		return fmt.Errorf("me should have failed")
	}
	if err.Error() != "403" {
		return fmt.Errorf("me expected 403")
	}
	fmt.Printf("me expected error: %v\n", err)

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
