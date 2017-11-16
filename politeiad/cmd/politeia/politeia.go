// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/util"
)

var (
	defaultHomeDir          = dcrutil.AppDataDir("politeia", false)
	defaultIdentityFilename = "identity.json"

	identityFilename = flag.String("-id", filepath.Join(defaultHomeDir,
		defaultIdentityFilename), "remote server identity file")
	testnet   = flag.Bool("testnet", false, "Use testnet port")
	printJson = flag.Bool("json", false, "Print JSON")
	verbose   = flag.Bool("v", false, "Verbose")
	rpcuser   = flag.String("rpcuser", "", "RPC user name for privileged calls")
	rpcpass   = flag.String("rpcpass", "", "RPC password for privileged calls")
	rpchost   = flag.String("rpchost", "", "RPC host")
	rpccert   = flag.String("rpccert", "", "RPC certificate")

	verify = false // Validate server TLS certificate
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeia [flags] <action> [arguments]\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n actions:\n")
	fmt.Fprintf(os.Stderr, "  identity          - Retrieve server "+
		"identity\n")
	fmt.Fprintf(os.Stderr, "  inventory         - Inventory proposals "+
		"<vetted count> <branches count>\n")
	fmt.Fprintf(os.Stderr, "  new               - Create new proposal "+
		"<name> <filename>...\n")
	fmt.Fprintf(os.Stderr, "  getunvetted       - Retrieve proposal "+
		"<id>\n")
	fmt.Fprintf(os.Stderr, "  setunvettedstatus - Set unvetted proposal "+
		"status <publish|censor> <id>\n")
	//fmt.Fprintf(os.Stderr, "  update      - Update proposal\n")

	fmt.Fprintf(os.Stderr, "\n")
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(defaultHomeDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

func getIdentity() error {
	// Fetch remote identity
	id, err := util.RemoteIdentity(verify, *rpchost, *rpccert)
	if err != nil {
		return err
	}

	rf := filepath.Join(defaultHomeDir, defaultIdentityFilename)

	// Pretty print identity.
	fmt.Printf("Key        : %x\n", id.Key)
	fmt.Printf("Fingerprint: %v\n", id.Fingerprint())

	// Ask user if we like this identity
	fmt.Printf("\nSave to %v or ctrl-c to abort ", rf)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if err = scanner.Err(); err != nil {
		return err
	}
	if len(scanner.Text()) != 0 {
		rf = scanner.Text()
	}
	rf = cleanAndExpandPath(rf)

	// Save identity
	err = os.MkdirAll(filepath.Dir(rf), 0700)
	if err != nil {
		return err
	}
	err = id.SavePublicIdentity(rf)
	if err != nil {
		return err
	}
	fmt.Printf("Identity saved to: %v\n", rf)

	return nil
}

func printCensorshipRecord(c v1.CensorshipRecord) {
	fmt.Printf("  Censorship record:\n")
	fmt.Printf("    Merkle   : %v\n", c.Merkle)
	fmt.Printf("    Token    : %v\n", c.Token)
	fmt.Printf("    Signature: %v\n", c.Signature)
}

func printProposalRecord(header string, pr v1.ProposalRecord) {
	// Pretty print proposal
	fmt.Printf("STATUS %v\n", pr.Status)
	status, ok := v1.PropStatus[pr.Status]
	if !ok {
		status = v1.PropStatus[v1.PropStatusInvalid]
	}
	fmt.Printf("%v:\n", header)
	fmt.Printf("  Name       : %v\n", pr.Name)
	fmt.Printf("  Status     : %v\n", status)
	fmt.Printf("  Timestamp  : %v\n", time.Unix(pr.Timestamp, 0).UTC())
	printCensorshipRecord(pr.CensorshipRecord)
	for k, v := range pr.Files {
		fmt.Printf("  File (%02v)  :\n", k)
		fmt.Printf("    Name     : %v\n", v.Name)
		fmt.Printf("    MIME     : %v\n", v.MIME)
		fmt.Printf("    Digest   : %v\n", v.Digest)
	}
}

func remoteInventory() (*v1.InventoryReply, error) {
	challenge, err := util.Random(v1.ChallengeSize)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(v1.Inventory{
		Challenge: hex.EncodeToString(challenge),
	})
	if err != nil {
		return nil, err
	}

	if *printJson {
		fmt.Println(string(b))
	}

	c, err := util.NewClient(verify, *rpccert)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", *rpchost+v1.InventoryRoute,
		bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(*rpcuser, *rpcpass)
	r, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		e, err := util.GetErrorFromJSON(r.Body)
		if err != nil {
			return nil, fmt.Errorf("%v", r.Status)
		}
		return nil, fmt.Errorf("%v: %v", r.Status, e)
	}

	bodyBytes := util.ConvertBodyToByteArray(r.Body, *printJson)

	var ir v1.InventoryReply
	err = json.Unmarshal(bodyBytes, &ir)
	if err != nil {
		return nil, fmt.Errorf("Could node unmarshal "+
			"InventoryReply: %v", err)
	}

	// Fetch remote identity
	id, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return nil, err
	}

	err = util.VerifyChallenge(id, challenge, ir.Response)
	if err != nil {
		return nil, err
	}

	return &ir, nil
}

func inventory() error {
	flags := flag.Args()[1:] // Chop off action.
	if len(flags) < 2 {
		return fmt.Errorf("vetted and branches counts expected")
	}

	i, err := remoteInventory()
	if err != nil {
		return err
	}

	if !*printJson {
		for _, v := range i.Vetted {
			printProposalRecord("Vetted proposal", v)
		}
		for _, v := range i.Branches {
			printProposalRecord("Unvetted proposal", v)
		}
	}

	return nil
}

func newProposal() error {
	flags := flag.Args()[1:] // Chop off action.

	// Make sure we have name and at least one file.
	if len(flags) < 2 {
		return fmt.Errorf("must provide name and at least one file")
	}

	// Fetch remote identity
	id, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	// Create New command
	challenge, err := util.Random(v1.ChallengeSize)
	if err != nil {
		return err
	}
	n := v1.New{
		Name:      flags[0],
		Challenge: hex.EncodeToString(challenge),
		Files:     make([]v1.File, 0, len(flags[1:])),
	}

	// Open all files, validate MIME type and digest them.
	hashes := make([]*[sha256.Size]byte, 0, len(flags[1:]))
	for i, a := range flags[1:] {
		file := v1.File{
			Name: filepath.Base(a),
		}
		file.MIME, file.Digest, file.Payload, err = util.LoadFile(a)
		if err != nil {
			return err
		}
		n.Files = append(n.Files, file)

		// Get digest
		digest, err := hex.DecodeString(file.Digest)
		if err != nil {
			return err
		}

		// Store for merkle root verification later
		var digest32 [sha256.Size]byte
		copy(digest32[:], digest)
		hashes = append(hashes, &digest32)

		fmt.Printf("%02v: %v %v %v\n",
			i, file.Digest, file.Name, file.MIME)
	}
	fmt.Printf("Submitted proposal name: %v\n", n.Name)

	// Convert Verify to JSON
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}

	if *printJson {
		fmt.Println(string(b))
	}

	c, err := util.NewClient(verify, *rpccert)
	if err != nil {
		return err
	}
	r, err := c.Post(*rpchost+v1.NewRoute, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := util.GetErrorFromJSON(r.Body)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	bodyBytes := util.ConvertBodyToByteArray(r.Body, *printJson)

	var reply v1.NewReply
	err = json.Unmarshal(bodyBytes, &reply)
	if err != nil {
		return fmt.Errorf("Could node unmarshal NewReply: %v", err)
	}

	// Verify challenge.
	err = util.VerifyChallenge(id, challenge, reply.Response)
	if err != nil {
		return err
	}

	// Convert merkle, token and signature to verify reply.
	root, err := hex.DecodeString(reply.CensorshipRecord.Merkle)
	if err != nil {
		return err
	}
	token, err := hex.DecodeString(reply.CensorshipRecord.Token)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(reply.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	var signature [identity.SignatureSize]byte
	copy(signature[:], sig)

	// Verify merkle root.
	if !bytes.Equal(merkle.Root(hashes)[:], root) {
		return fmt.Errorf("invalid merkle root")
	}

	// Verify proposal token signature.
	merkleToken := make([]byte, len(root)+len(token))
	copy(merkleToken, root[:])
	copy(merkleToken[len(root[:]):], token)
	if !id.VerifyMessage(merkleToken, signature) {
		return fmt.Errorf("verification failed")
	}

	if !*printJson {
		printCensorshipRecord(reply.CensorshipRecord)
	}

	return nil
}

func getUnvetted() error {
	flags := flag.Args()[1:] // Chop off action.

	// Make sure we have the censorship token
	if len(flags) != 1 {
		return fmt.Errorf("must provide one and only one censorship " +
			"token")
	}

	// Validate censorship token
	_, err := util.ConvertStringToken(flags[0])
	if err != nil {
		return err
	}

	// Fetch remote identity
	id, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	// Create New command
	challenge, err := util.Random(v1.ChallengeSize)
	if err != nil {
		return err
	}
	n := v1.GetUnvetted{
		Challenge: hex.EncodeToString(challenge),
		Token:     flags[0],
	}

	// Convert to JSON
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}

	if *printJson {
		fmt.Println(string(b))
	}

	c, err := util.NewClient(verify, *rpccert)
	if err != nil {
		return err
	}
	r, err := c.Post(*rpchost+v1.GetUnvettedRoute, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := util.GetErrorFromJSON(r.Body)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	bodyBytes := util.ConvertBodyToByteArray(r.Body, *printJson)

	var reply v1.GetUnvettedReply
	err = json.Unmarshal(bodyBytes, &reply)
	if err != nil {
		return fmt.Errorf("Could not unmarshal GetUnvettedReply: %v",
			err)
	}

	// Verify challenge.
	err = util.VerifyChallenge(id, challenge, reply.Response)
	if err != nil {
		return err
	}

	// Verify status
	if reply.Proposal.Status == v1.PropStatusInvalid ||
		reply.Proposal.Status == v1.PropStatusNotFound {
		// Pretty print proposal
		status, ok := v1.PropStatus[reply.Proposal.Status]
		if !ok {
			status = v1.PropStatus[v1.PropStatusInvalid]
		}
		fmt.Printf("Proposal     : %v\n", flags[0])
		fmt.Printf("  Status     : %v\n", status)
		return nil
	}

	// Verify content
	err = v1.Verify(*id, reply.Proposal.CensorshipRecord,
		reply.Proposal.Files)
	if err != nil {
		return err
	}

	if !*printJson {
		printProposalRecord("Unvetted proposal", reply.Proposal)
	}
	return nil
}

func getVetted() error {
	flags := flag.Args()[1:] // Chop off action.

	// Make sure we have the censorship token
	if len(flags) != 1 {
		return fmt.Errorf("must provide one and only one censorship " +
			"token")
	}

	// Validate censorship token
	_, err := util.ConvertStringToken(flags[0])
	if err != nil {
		return err
	}

	// Fetch remote identity
	id, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	// Create New command
	challenge, err := util.Random(v1.ChallengeSize)
	if err != nil {
		return err
	}
	n := v1.GetVetted{
		Challenge: hex.EncodeToString(challenge),
		Token:     flags[0],
	}

	// Convert to JSON
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}

	if *printJson {
		fmt.Println(string(b))
	}

	c, err := util.NewClient(verify, *rpccert)
	if err != nil {
		return err
	}
	r, err := c.Post(*rpchost+v1.GetVettedRoute, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := util.GetErrorFromJSON(r.Body)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	bodyBytes := util.ConvertBodyToByteArray(r.Body, *printJson)

	var reply v1.GetVettedReply
	err = json.Unmarshal(bodyBytes, &reply)
	if err != nil {
		return fmt.Errorf("Could not unmarshal GetVettedReply: %v",
			err)
	}

	// Verify challenge.
	err = util.VerifyChallenge(id, challenge, reply.Response)
	if err != nil {
		return err
	}

	// Verify status
	if reply.Proposal.Status == v1.PropStatusInvalid ||
		reply.Proposal.Status == v1.PropStatusNotFound {
		// Pretty print proposal
		status, ok := v1.PropStatus[reply.Proposal.Status]
		if !ok {
			status = v1.PropStatus[v1.PropStatusInvalid]
		}
		fmt.Printf("Proposal     : %v\n", flags[0])
		fmt.Printf("  Status     : %v\n", status)
		return nil
	}

	// Verify content
	err = v1.Verify(*id, reply.Proposal.CensorshipRecord,
		reply.Proposal.Files)
	if err != nil {
		return err
	}

	if !*printJson {
		printProposalRecord("Vetted proposal", reply.Proposal)
	}
	return nil
}

func convertStatus(s string) (v1.PropStatusT, error) {
	switch s {
	case "censor":
		return v1.PropStatusCensored, nil
	case "publish":
		return v1.PropStatusPublic, nil
	}

	return v1.PropStatusInvalid, fmt.Errorf("invalid status")
}

func setUnvettedStatus() error {
	flags := flag.Args()[1:] // Chop off action.

	// Make sure we have the status and the censorship token
	if len(flags) != 2 {
		return fmt.Errorf("must provide status and censorship token")
	}

	// Verify we got a valid status
	status, err := convertStatus(flags[0])
	if err != nil {
		return err
	}

	// Validate censorship token
	_, err = util.ConvertStringToken(flags[1])
	if err != nil {
		return err
	}

	// Fetch remote identity
	id, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	// Create New command
	challenge, err := util.Random(v1.ChallengeSize)
	if err != nil {
		return err
	}
	n := v1.SetUnvettedStatus{
		Challenge: hex.EncodeToString(challenge),
		Status:    status,
		Token:     flags[1],
	}

	// Convert to JSON
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}

	if *printJson {
		fmt.Println(string(b))
	}

	c, err := util.NewClient(verify, *rpccert)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", *rpchost+v1.SetUnvettedStatusRoute,
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.SetBasicAuth(*rpcuser, *rpcpass)
	r, err := c.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := util.GetErrorFromJSON(r.Body)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	bodyBytes := util.ConvertBodyToByteArray(r.Body, *printJson)

	var reply v1.SetUnvettedStatusReply
	err = json.Unmarshal(bodyBytes, &reply)
	if err != nil {
		return fmt.Errorf("Could not unmarshal "+
			"SetUnvettedStatusReply: %v", err)
	}

	// Verify challenge.
	err = util.VerifyChallenge(id, challenge, reply.Response)
	if err != nil {
		return err
	}

	if !*printJson {
		// Pretty print proposal
		status, ok := v1.PropStatus[reply.Status]
		if !ok {
			status = v1.PropStatus[v1.PropStatusInvalid]
		}
		fmt.Printf("Set proposal status:\n")
		fmt.Printf("  Status   : %v\n", status)
	}

	return nil
}

func _main() error {
	flag.Parse()
	if len(flag.Args()) == 0 {
		usage()
		return fmt.Errorf("must provide action")
	}

	if *rpchost == "" {
		if *testnet {
			*rpchost = v1.DefaultTestnetHost
		} else {
			*rpchost = v1.DefaultMainnetHost
		}
	} else {
		// For now assume we can't verify server TLS certificate
		verify = true
	}

	port := v1.DefaultMainnetPort
	if *testnet {
		port = v1.DefaultTestnetPort
	}

	*rpchost = util.NormalizeAddress(*rpchost, port)

	// Set port if not specified.
	u, err := url.Parse("https://" + *rpchost)
	if err != nil {
		return err
	}
	*rpchost = u.String()

	// Scan through command line arguments.
	for i, a := range flag.Args() {
		// Select action
		if i == 0 {
			switch a {
			case "new":
				return newProposal()
			case "identity":
				return getIdentity()
			case "inventory":
				return inventory()
			case "getunvetted":
				return getUnvetted()
			case "getvetted":
				return getVetted()
			case "setunvettedstatus":
				return setUnvettedStatus()
			default:
				return fmt.Errorf("invalid action: %v", a)
			}
		}
	}

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
