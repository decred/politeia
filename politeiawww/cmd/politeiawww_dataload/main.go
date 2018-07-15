package main

import (
	"bufio"
	"bytes"
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
	"github.com/decred/politeia/politeiawww/api/v1"
	cliconfig "github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
	wwwconfig "github.com/decred/politeia/politeiawww/sharedconfig"
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
		"--mailhost", "",
		"--mailuser", "",
		"--mailpass", "",
		"--proxy", "0",
		"--webserveraddress", "",
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
	politeiadCmd = executeCommand("politeiad", "--testnet")
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

func createUserWithDbutil(email, username, password string) error {
	fmt.Printf("Creating user: %v\n", email)
	var out bytes.Buffer
	var stderr bytes.Buffer

	cmd := executeCommand(
		dbutil,
		"-testnet",
		"-newuser",
		email,
		username,
		password)

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Start()

	if err != nil {
		return fmt.Errorf(fmt.Sprint(err) + ": " + stderr.String())
	}

	err = cmd.Wait()

	if err != nil {
		return fmt.Errorf(fmt.Sprint(err) + ": " + stderr.String())
	}
	return nil
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

func clearPaywall(email string) error {
	fmt.Printf("Clearing paywall for user: %v\n", email)
	cmd := executeCommand(
		dbutil,
		"-testnet",
		"-clearpaywall",
		email)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}

func createPaidUsers() error {
	err := startPoliteiad()
	if err != nil {
		return err
	}

	err = startPoliteiawww(false)
	if err != nil {
		return err
	}

	err = createUserWithPoliteiawww(cfg.AdminEmail, cfg.AdminUser, cfg.AdminPass)
	if err != nil {
		return err
	}

	err = createUserWithPoliteiawww(cfg.PaidEmail, cfg.PaidUser, cfg.PaidPass)
	if err != nil {
		return err
	}

	stopServers()

	err = setAdmin(cfg.AdminEmail)
	if err != nil {
		return err
	}

	err = clearPaywall(cfg.AdminEmail)
	if err != nil {
		return err
	}

	return clearPaywall(cfg.PaidEmail)
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
	fullArgs = append(fullArgs, args...)
	cmd := executeCommand(fullArgs...)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return err
	}
	defer cmd.Wait()

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

	errBytes, err := ioutil.ReadAll(stderr)
	if err != nil {
		return err
	}

	if len(errBytes) > 0 {
		return fmt.Errorf("unexpected error output from %v: %v", cli,
			string(errBytes))
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

func setProposalStatus(token string, status v1.PropStatusT) error {
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
		strconv.FormatInt(int64(status), 10))
}

func createProposals() error {
	// Create the proposals.
	if err := login(cfg.PaidEmail, cfg.PaidPass); err != nil {
		return err
	}
	publishedProposalToken, err := createProposal()
	if err != nil {
		return err
	}
	censoredProposalToken, err := createProposal()
	if err != nil {
		return err
	}
	if _, err := createProposal(); err != nil {
		return err
	}

	// Set the proposals' status.
	if err := login(cfg.AdminEmail, cfg.AdminPass); err != nil {
		return err
	}
	if err := setProposalStatus(publishedProposalToken, v1.PropStatusPublic); err != nil {
		return err
	}
	if err := setProposalStatus(censoredProposalToken, v1.PropStatusCensored); err != nil {
		return err
	}
	if err := logout(); err != nil {
		return err
	}

	// Create comments on the published proposal.
	if err := login(cfg.AdminEmail, cfg.AdminPass); err != nil {
		return err
	}
	commentID, err := createComment("", publishedProposalToken)
	if err != nil {
		return err
	}
	if err := logout(); err != nil {
		return err
	}

	if err := login(cfg.PaidEmail, cfg.PaidPass); err != nil {
		return err
	}
	if _, err := createComment(commentID, publishedProposalToken); err != nil {
		return err
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
	cmd := executeCommand(cli, "logout")
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}

func handleError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
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
	return os.RemoveAll(cliconfig.HomeDir)
}

func stopPoliteiad() {
	if politeiadCmd != nil {
		fmt.Printf("Stopping politeiad\n")
		politeiadCmd.Process.Kill()
		politeiadCmd = nil
	}
}

func stopPoliteiawww() {
	if politeiawwwCmd != nil {
		fmt.Printf("Stopping politeiawww\n")
		politeiawwwCmd.Process.Kill()
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

	if err = createPaidUsers(); err != nil {
		return err
	}

	if err = startPoliteiad(); err != nil {
		return err
	}

	if err = startPoliteiawww(true); err != nil {
		return err
	}

	if err = createUnpaidUsers(); err != nil {
		return err
	}

	stopPoliteiawww()
	if err = startPoliteiawww(false); err != nil {
		return err
	}

	if err = createProposals(); err != nil {
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
