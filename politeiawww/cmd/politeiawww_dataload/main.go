// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrutil"
	"github.com/thi4go/politeia/politeiawww/api/www/v1"
	wwwconfig "github.com/thi4go/politeia/politeiawww/sharedconfig"
)

type beforeVerifyReply func() interface{}
type verifyReply func() bool

const (
	cli    = "politeiawwwcli"
	dbutil = "politeiawww_dbutil"
)

var (
	cfg            *config
	politeiadCmd   *exec.Cmd
	politeiawwwCmd *exec.Cmd
)

func executeCommand(args ...string) *exec.Cmd {
	if cfg.Verbose {
		fmt.Printf("  $ %v\n", strings.Join(args, " "))
	}
	return exec.Command(args[0], args[1:]...)
}

func createPoliteiawwCmd(paywall bool) *exec.Cmd {
	var paywallXPub string
	var paywallAmount uint64
	if paywall {
		paywallXPub = "tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFmuMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx"
		paywallAmount = 10000000
	}

	return executeCommand(
		"politeiawww",
		"--testnet",
		"--paywallxpub", paywallXPub,
		"--paywallamount", strconv.FormatUint(paywallAmount, 10),
		"--debuglevel", cfg.DebugLevel)
}

func createLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	/*
		if err != nil {
			return nil, err
		}

		_, err = file.Write([]byte("------------------------------------------------------\n"))
		return file, err
	*/
}

func waitForStartOfDay(out io.Reader) {
	buf := bufio.NewScanner(out)
	for buf.Scan() {
		text := buf.Text()
		if strings.Contains(text, "Start of day") {
			return
		}
	}
}

func startPoliteiawww(paywall bool) error {
	fmt.Printf("Starting politeiawww\n")
	politeiawwwCmd = createPoliteiawwCmd(paywall)
	out, _ := politeiawwwCmd.StdoutPipe()
	if err := politeiawwwCmd.Start(); err != nil {
		politeiawwwCmd = nil
		return err
	}

	logFile, err := createLogFile(cfg.PoliteiawwwLogFile)
	if err != nil {
		return err
	}

	reader := io.TeeReader(out, logFile)
	waitForStartOfDay(reader)
	go io.Copy(logFile, out)

	// Get the version for the csrf
	return getVersionFromPoliteiawww()
}

func startPoliteiad() error {
	fmt.Printf("Starting politeiad\n")
	politeiadCmd = executeCommand("politeiad", "--testnet", "--buildcache")
	out, _ := politeiadCmd.StdoutPipe()
	if err := politeiadCmd.Start(); err != nil {
		politeiadCmd = nil
		return err
	}

	logFile, err := createLogFile(cfg.PoliteiadLogFile)
	if err != nil {
		return err
	}

	reader := io.TeeReader(out, logFile)
	waitForStartOfDay(reader)
	return nil
}

func getVersionFromPoliteiawww() error {
	fmt.Printf("Getting version\n")

	var vr *v1.VersionReply
	return executeCliCommand(
		func() interface{} {
			vr = &v1.VersionReply{}
			return vr
		},
		func() bool {
			return vr.PubKey != ""
		},
		"version",
	)
}

func createUserWithPoliteiawww(email, username, password string) error {
	fmt.Printf("Creating user: %v\n", email)

	var nur *v1.NewUserReply
	receivedNewUserReply := new(bool)
	return executeCliCommand(
		func() interface{} {
			nur = &v1.NewUserReply{}
			return nur
		},
		func() bool {
			if *receivedNewUserReply && nur.VerificationToken == "" {
				return true
			}

			if !*receivedNewUserReply && nur.VerificationToken != "" {
				*receivedNewUserReply = true
			}

			return false
		},
		"newuser",
		email,
		username,
		password,
		"--verify",
	)
}

func setAdmin(email string) error {
	fmt.Printf("Elevating user to admin: %v\n", email)
	cmd := executeCommand(
		dbutil,
		"-testnet",
		"-setadmin",
		email,
		"true")
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}

func clearPaywall(userID string) error {
	fmt.Printf("Clearing paywall for user with ID: %v\n", userID)
	var eur *v1.ManageUserReply
	return executeCliCommand(
		func() interface{} {
			eur = &v1.ManageUserReply{}
			return eur
		},
		func() bool {
			return *eur == (v1.ManageUserReply{})
		},
		"manageuser",
		userID,
		fmt.Sprintf("%v", v1.UserManageClearUserPaywall),
		"politeaiwww_dataload")
}

func addProposalCredits(email, quantity string) error {
	fmt.Printf("Adding %v proposal credits to user account: %v\n", quantity, email)
	cmd := executeCommand(
		dbutil,
		"-testnet",
		"-addcredits",
		email,
		quantity)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}

func me() (*v1.LoginReply, error) {
	fmt.Printf("Fetching user details\n")
	var lr *v1.LoginReply
	err := executeCliCommand(
		func() interface{} {
			lr = &v1.LoginReply{}
			return lr
		},
		func() bool {
			return lr.UserID != ""
		},
		"me")
	if err != nil {
		return nil, err
	}
	return lr, nil
}

func createPaidUsers() error {
	err := createUserWithPoliteiawww(cfg.AdminEmail, cfg.AdminUser, cfg.AdminPass)
	if err != nil {
		return err
	}

	err = createUserWithPoliteiawww(cfg.PaidEmail, cfg.PaidUser, cfg.PaidPass)
	if err != nil {
		return err
	}

	stopServers()

	if err = setAdmin(cfg.AdminEmail); err != nil {
		return err
	}

	if err = addProposalCredits(cfg.AdminEmail, "5"); err != nil {
		return err
	}

	if err = startPoliteiad(); err != nil {
		return err
	}

	if err = startPoliteiawww(true); err != nil {
		return err
	}

	if err = login(cfg.AdminEmail, cfg.AdminPass); err != nil {
		return err
	}
	if err := updateUserKey(); err != nil {
		return err
	}

	// Fetch userIDs for admin user and paid user
	lr, err := me()
	if err != nil {
		return err
	}
	adminID := lr.UserID

	if err = login(cfg.PaidEmail, cfg.PaidPass); err != nil {
		return err
	}
	lr, err = me()
	if err != nil {
		return nil
	}
	paidID := lr.UserID

	// Log back in with admin and clear paywalls
	if err = login(cfg.AdminEmail, cfg.AdminPass); err != nil {
		return err
	}

	if err = clearPaywall(adminID); err != nil {
		return err
	}

	return clearPaywall(paidID)
}

func createUnpaidUsers() error {
	return createUserWithPoliteiawww(cfg.UnpaidEmail, cfg.UnpaidUser, cfg.UnpaidPass)
}

func executeCliCommand(beforeVerify beforeVerifyReply, verify verifyReply, args ...string) error {
	fullArgs := make([]string, 0, len(args)+2)
	fullArgs = append(fullArgs, cli)
	fullArgs = append(fullArgs, "--host")
	fullArgs = append(fullArgs, "https://127.0.0.1:4443")
	fullArgs = append(fullArgs, "--json")
	fullArgs = append(fullArgs, "--skipverify")
	fullArgs = append(fullArgs, args...)
	cmd := executeCommand(fullArgs...)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return err
	}
	defer cmd.Wait()

	errBytes, err := ioutil.ReadAll(stderr)
	if err != nil {
		return err
	}

	if len(errBytes) > 0 {
		return fmt.Errorf("unexpected error output from %v: %v", cli,
			string(errBytes))
	}

	var allText string
	buf := bufio.NewScanner(stdout)
	for buf.Scan() {
		text := buf.Text()

		var lines []string
		if strings.Contains(text, "\n") {
			lines = strings.Split(text, "\n")
		} else {
			lines = append(lines, text)
		}

		for _, line := range lines {
			if cfg.Verbose {
				fmt.Printf("  %v\n", line)
			}

			var er v1.ErrorReply
			err := json.Unmarshal([]byte(line), &er)
			if err == nil && er.ErrorCode != int64(v1.ErrorStatusInvalid) {
				return fmt.Errorf("error returned from %v: %v %v", cli,
					er.ErrorCode, er.ErrorContext)
			}

			reply := beforeVerify()
			err = json.Unmarshal([]byte(line), reply)
			if err == nil && verify() {
				return nil
			}

			allText += line + "\n"
		}
	}

	if err := buf.Err(); err != nil {
		return err
	}

	return fmt.Errorf("unexpected output from %v: %v", cli, allText)
}

func createProposal() (string, error) {
	fmt.Printf("Creating proposal\n")

	var npr *v1.NewProposalReply
	err := executeCliCommand(
		func() interface{} {
			npr = &v1.NewProposalReply{}
			return npr
		},
		func() bool {
			return npr.CensorshipRecord.Token != ""
		},
		"newproposal",
		"--random",
	)
	if err != nil {
		return "", err
	}

	fmt.Printf("Created proposal with token %v\n", npr.CensorshipRecord.Token)
	return npr.CensorshipRecord.Token, nil
}

func checkProposal(token string) error {
	fmt.Printf("Checking proposal with token %v\n", token)

	var pdr *v1.ProposalDetailsReply
	err := executeCliCommand(
		func() interface{} {
			pdr = &v1.ProposalDetailsReply{}
			return pdr
		},
		func() bool {
			return pdr.Proposal.CensorshipRecord.Token == token
		},
		"proposaldetails",
		token,
	)
	if err != nil {
		return err
	}

	fmt.Printf("Verified proposal\n")
	return nil
}

func createComment(parentID, token string) (string, error) {
	fmt.Printf("Creating comment\n")

	var ncr *v1.NewCommentReply
	err := executeCliCommand(
		func() interface{} {
			ncr = &v1.NewCommentReply{}
			return ncr
		},
		func() bool {
			return ncr.Comment.CommentID != ""
		},
		"newcomment",
		token,
		"This is a comment",
		parentID)
	if err != nil {
		return "", err
	}

	fmt.Printf("Created comment with id %v\n", ncr.Comment.CommentID)
	return ncr.Comment.CommentID, nil
}

func setProposalStatus(token string, status v1.PropStatusT, message string) error {
	fmt.Printf("Setting proposal status to %v\n", status)

	var spsr *v1.SetProposalStatusReply
	return executeCliCommand(
		func() interface{} {
			spsr = &v1.SetProposalStatusReply{}
			return spsr
		},
		func() bool {
			return spsr.Proposal.Status != v1.PropStatusInvalid
		},
		"setproposalstatus",
		token,
		strconv.FormatInt(int64(status), 10),
		message,
	)
}

func publishProposals(number int) ([]string, error) {
	var proposalsTokens []string

	for i := 0; i < number; i++ {
		token, err := createProposal()
		if err != nil {
			return nil, err
		}
		proposalsTokens = append(proposalsTokens, token)
	}

	return proposalsTokens, nil
}

func createProposals(vettedProps int, unvettedProps int, commentsNumber int) error {
	// Create the proposals.
	if err := login(cfg.PaidEmail, cfg.PaidPass); err != nil {
		return err
	}
	if err := updateUserKey(); err != nil {
		return err
	}

	vettedProposalTokens, err := publishProposals(vettedProps)
	if err != nil {
		return err
	}

	unvettedProposalTokens, err := publishProposals(unvettedProps)
	if err != nil {
		return err
	}

	for i := 0; i < vettedProps; i++ {
		err := checkProposal(vettedProposalTokens[i])
		if err != nil {
			return err
		}
	}
	for i := 0; i < unvettedProps; i++ {
		err := checkProposal(unvettedProposalTokens[i])
		if err != nil {
			return err
		}
	}

	// Set the proposals' status.
	if err := login(cfg.AdminEmail, cfg.AdminPass); err != nil {
		return err
	}
	if err := updateUserKey(); err != nil {
		return err
	}

	for i := 0; i < vettedProps; i++ {
		if err := setProposalStatus(vettedProposalTokens[i], v1.PropStatusPublic, ""); err != nil {
			return err
		}
	}

	// Censor the first unvetted proposal
	if len(unvettedProposalTokens) > 0 {
		if err := setProposalStatus(unvettedProposalTokens[0], v1.PropStatusCensored, "censor message"); err != nil {
			return err
		}
	}

	if err := logout(); err != nil {
		return err
	}

	// Create comments on the first public published proposal.
	if err := login(cfg.AdminEmail, cfg.AdminPass); err != nil {
		return err
	}
	if err := updateUserKey(); err != nil {
		return err
	}

	var commentID string
	for i := 0; i < commentsNumber; i++ {
		if len(vettedProposalTokens) > 0 {
			commentID, err = createComment("", vettedProposalTokens[0])
			if err != nil {
				return err
			}
		}
	}

	if err := logout(); err != nil {
		return err
	}

	if err := login(cfg.PaidEmail, cfg.PaidPass); err != nil {
		return err
	}
	if err := updateUserKey(); err != nil {
		return err
	}
	if len(vettedProposalTokens) > 0 {
		if _, err := createComment(commentID, vettedProposalTokens[0]); err != nil {
			return err
		}
	}
	return logout()
}

func login(email, password string) error {
	fmt.Printf("Logging in as: %v\n", email)
	var lr *v1.LoginReply
	return executeCliCommand(
		func() interface{} {
			lr = &v1.LoginReply{}
			return lr
		},
		func() bool {
			return lr.UserID != ""
		},
		"login",
		email,
		password)
}

func logout() error {
	fmt.Printf("Logging out...\n")
	return executeCliCommand(
		func() interface{} {
			return &v1.LogoutReply{}
		},
		func() bool {
			return true
		},
		"logout")
}

func updateUserKey() error {
	fmt.Printf("Updating user key\n")
	return executeCliCommand(
		func() interface{} {
			return &v1.UpdateUserKeyReply{}
		},
		func() bool {
			return true
		},
		"updateuserkey")
}

func deleteExistingData() error {
	fmt.Printf("Deleting existing data\n")

	// politeiad data dir
	politeiadDataDir := filepath.Join(dcrutil.AppDataDir("politeiad", false), "data")
	if err := os.RemoveAll(politeiadDataDir); err != nil {
		return err
	}

	// politeiawww data dir
	if err := os.RemoveAll(wwwconfig.DefaultDataDir); err != nil {
		return err
	}

	// politeiawww cli dir
	cliDataDir := filepath.Join(wwwconfig.DefaultHomeDir, "cli", "data")
	return os.RemoveAll(cliDataDir)
}

func stopPoliteiad() {
	if politeiadCmd != nil {
		fmt.Printf("Stopping politeiad\n")
		if err := politeiadCmd.Process.Kill(); err != nil {
			fmt.Fprintf(os.Stderr, "unable to kill politeiad: %v", err)
		}
		politeiadCmd = nil
	}
}

func stopPoliteiawww() {
	if politeiawwwCmd != nil {
		fmt.Printf("Stopping politeiawww\n")
		if err := politeiawwwCmd.Process.Kill(); err != nil {
			fmt.Fprintf(os.Stderr, "unable to kill politeiawww: %v", err)
		}
		politeiawwwCmd = nil
	}
}

func stopServers() {
	stopPoliteiad()
	stopPoliteiawww()
}

func _main() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	var err error
	cfg, err = loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}

	if cfg.DeleteData {
		if err = deleteExistingData(); err != nil {
			return err
		}
	}

	if err = startPoliteiad(); err != nil {
		return err
	}

	if err = startPoliteiawww(true); err != nil {
		return err
	}

	if err = createPaidUsers(); err != nil {
		return err
	}

	if err = createUnpaidUsers(); err != nil {
		return err
	}

	stopPoliteiawww()
	if err = startPoliteiawww(false); err != nil {
		return err
	}

	err = createProposals(cfg.VettedPropsNumber, cfg.UnvettedPropsNumber,
		cfg.CommentsNumber)
	if err != nil {
		return err
	}

	fmt.Printf("Load data complete\n")
	return nil
}

func main() {
	err := _main()
	stopServers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
