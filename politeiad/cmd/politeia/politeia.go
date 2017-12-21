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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/util"
)

const allowInteractive = "i-know-this-is-a-bad-idea"

var (
	regexMD          = regexp.MustCompile(`^metadata[\d]{1,2}:`)
	regexMDID        = regexp.MustCompile(`[\d]{1,2}`)
	regexAppendMD    = regexp.MustCompile(`^appendmetadata[\d]{1,2}:`)
	regexOverwriteMD = regexp.MustCompile(`^overwritemetadata[\d]{1,2}:`)
	regexFileAdd     = regexp.MustCompile(`^add:`)
	regexFileDel     = regexp.MustCompile(`^del:`)
	regexToken       = regexp.MustCompile(`^token:`)

	defaultHomeDir          = dcrutil.AppDataDir("politeia", false)
	defaultIdentityFilename = "identity.json"

	identityFilename = flag.String("-id", filepath.Join(defaultHomeDir,
		defaultIdentityFilename), "remote server identity file")
	testnet     = flag.Bool("testnet", false, "Use testnet port")
	printJson   = flag.Bool("json", false, "Print JSON")
	verbose     = flag.Bool("v", false, "Verbose")
	rpcuser     = flag.String("rpcuser", "", "RPC user name for privileged calls")
	rpcpass     = flag.String("rpcpass", "", "RPC password for privileged calls")
	rpchost     = flag.String("rpchost", "", "RPC host")
	rpccert     = flag.String("rpccert", "", "RPC certificate")
	interactive = flag.String("interactive", "", "Set to "+
		allowInteractive+" to to turn off interactive mode during "+
		"identity fetch")

	verify = false // Validate server TLS certificate
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeia [flags] <action> [arguments]\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n actions:\n")
	fmt.Fprintf(os.Stderr, "  identity          - Retrieve server "+
		"identity\n")
	fmt.Fprintf(os.Stderr, "  plugins           - Retrieve plugin "+
		"inventory\n")
	fmt.Fprintf(os.Stderr, "  inventory         - Inventory records "+
		"<vetted count> <branches count>\n")
	fmt.Fprintf(os.Stderr, "  new               - Create new record "+
		"[metadata<id>]... <filename>...\n")
	fmt.Fprintf(os.Stderr, "  getunvetted       - Retrieve record "+
		"<id>\n")
	fmt.Fprintf(os.Stderr, "  setunvettedstatus - Set unvetted record "+
		"status <publish|censor> <id> [actionmdid:metadata]...\n")
	fmt.Fprintf(os.Stderr, "  update            - Update unvetted record "+
		"[actionmdid:metadata]... <actionfile:filename>... "+
		"token:<token>\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, " metadata<id> is the word metadata followed "+
		"by digits. Example with 2 metadata records "+
		"metadata0:{\"moo\":\"12\",\"blah\":\"baz\"} "+
		"metadata1:{\"lala\":42}\n")
	fmt.Fprintf(os.Stderr, " actionmdid is an action + metadatastream id "+
		"E.g. appendmetadata0:{\"foo\":\"bar\"} or "+
		"overwritemetadata12:{\"bleh\":\"truff\"}\n")

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

// getErrorFromResponse extracts a user-readable string from the response from
// politeiad, which will contain a JSON error.
func getErrorFromResponse(r *http.Response) (string, error) {
	var errMsg string
	decoder := json.NewDecoder(r.Body)
	if r.StatusCode == http.StatusInternalServerError {
		var e v1.ServerErrorReply
		if err := decoder.Decode(&e); err != nil {
			return "", err
		}
		errMsg = fmt.Sprintf("%v", e.ErrorCode)
	} else {
		var e v1.UserErrorReply
		if err := decoder.Decode(&e); err != nil {
			return "", err
		}
		errMsg = v1.ErrorStatus[e.ErrorCode] + " "
		if e.ErrorContext != nil && len(e.ErrorContext) > 0 {
			errMsg += strings.Join(e.ErrorContext, ", ")
		}
	}

	return errMsg, nil
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
	if *interactive != allowInteractive {
		fmt.Printf("\nSave to %v or ctrl-c to abort ", rf)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if err = scanner.Err(); err != nil {
			return err
		}
		if len(scanner.Text()) != 0 {
			rf = scanner.Text()
		}
	} else {
		fmt.Printf("Saving identity to %v\n", rf)
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

func printRecordRecord(header string, pr v1.Record) {
	// Pretty print record
	status, ok := v1.RecordStatus[pr.Status]
	if !ok {
		status = v1.RecordStatus[v1.RecordStatusInvalid]
	}
	fmt.Printf("%v:\n", header)
	fmt.Printf("  Status     : %v\n", status)
	fmt.Printf("  Timestamp  : %v\n", time.Unix(pr.Timestamp, 0).UTC())
	printCensorshipRecord(pr.CensorshipRecord)
	fmt.Printf("  Metadata   : %v\n", pr.Metadata)
	for k, v := range pr.Files {
		fmt.Printf("  File (%02v)  :\n", k)
		fmt.Printf("    Name     : %v\n", v.Name)
		fmt.Printf("    MIME     : %v\n", v.MIME)
		fmt.Printf("    Digest   : %v\n", v.Digest)
	}
}

func pluginInventory() (*v1.PluginInventoryReply, error) {
	challenge, err := util.Random(v1.ChallengeSize)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(v1.PluginInventory{
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
	req, err := http.NewRequest("POST", *rpchost+v1.PluginInventoryRoute,
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
		e, err := getErrorFromResponse(r)
		if err != nil {
			return nil, fmt.Errorf("%v", r.Status)
		}
		return nil, fmt.Errorf("%v: %v", r.Status, e)
	}

	bodyBytes := util.ConvertBodyToByteArray(r.Body, *printJson)

	var ir v1.PluginInventoryReply
	err = json.Unmarshal(bodyBytes, &ir)
	if err != nil {
		return nil, fmt.Errorf("Could node unmarshal "+
			"PluginInventoryReply: %v", err)
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

func plugin() error {
	flags := flag.Args()[1:] // Chop off action.

	if len(flags) != 4 {
		return fmt.Errorf("not enough parameters")
	}

	challenge, err := util.Random(v1.ChallengeSize)
	if err != nil {
		return err
	}
	b, err := json.Marshal(v1.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        flags[0],
		Command:   flags[1],
		CommandID: flags[2],
		Payload:   flags[3],
	})
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
	req, err := http.NewRequest("POST", *rpchost+v1.PluginCommandRoute,
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
		e, err := getErrorFromResponse(r)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	bodyBytes := util.ConvertBodyToByteArray(r.Body, *printJson)

	var pcr v1.PluginCommandReply
	err = json.Unmarshal(bodyBytes, &pcr)
	if err != nil {
		return fmt.Errorf("Could node unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Fetch remote identity
	id, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	err = util.VerifyChallenge(id, challenge, pcr.Response)
	if err != nil {
		return err
	}

	return nil
}

func getPluginInventory() error {
	pr, err := pluginInventory()
	if err != nil {
		return err
	}

	for _, v := range pr.Plugins {
		fmt.Printf("Plugin ID      : %v\n", v.ID)
		if len(v.Settings) > 0 {
			fmt.Printf("Plugin settings: %v = %v\n",
				v.Settings[0].Key,
				v.Settings[0].Value)
		}
		for _, vv := range v.Settings[1:] {
			fmt.Printf("                 %v = %v\n", vv.Key,
				vv.Value)
		}
	}

	return nil
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
		e, err := getErrorFromResponse(r)
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
			printRecordRecord("Vetted record", v)
		}
		for _, v := range i.Branches {
			printRecordRecord("Unvetted record", v)
		}
	}

	return nil
}

func getFile(filename string) (*v1.File, *[sha256.Size]byte, error) {
	var err error

	file := &v1.File{
		Name: filepath.Base(filename),
	}
	file.MIME, file.Digest, file.Payload, err = util.LoadFile(filename)
	if err != nil {
		return nil, nil, err
	}

	// Get digest
	digest, err := hex.DecodeString(file.Digest)
	if err != nil {
		return nil, nil, err
	}

	// Store for merkle root verification later
	var digest32 [sha256.Size]byte
	copy(digest32[:], digest)

	return file, &digest32, nil
}

func newRecord() error {
	flags := flag.Args()[1:] // Chop off action.

	// Fish out metadata records and filenames
	md := make([]v1.MetadataStream, 0, len(flags))
	filenames := make([]string, 0, len(flags))
	for _, v := range flags {
		mdRecord := regexMD.FindString(v)
		if mdRecord == "" {
			// Filename
			filenames = append(filenames, v)
			continue
		}

		id, err := strconv.ParseUint(regexMDID.FindString(mdRecord),
			10, 64)
		if err != nil {
			return err
		}
		md = append(md, v1.MetadataStream{
			ID:      id,
			Payload: v[len(mdRecord):],
		})
	}

	if len(filenames) == 0 {
		return fmt.Errorf("no filenames provided")
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
	n := v1.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata:  md,
		Files:     make([]v1.File, 0, len(flags[1:])),
	}

	// Open all files, validate MIME type and digest them.
	hashes := make([]*[sha256.Size]byte, 0, len(flags[1:]))
	for i, a := range filenames {
		file, digest, err := getFile(a)
		if err != nil {
			return err
		}
		n.Files = append(n.Files, *file)
		hashes = append(hashes, digest)

		fmt.Printf("%02v: %v %v %v\n",
			i, file.Digest, file.Name, file.MIME)
	}
	fmt.Printf("Record submitted\n")

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
	r, err := c.Post(*rpchost+v1.NewRecordRoute, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := getErrorFromResponse(r)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	bodyBytes := util.ConvertBodyToByteArray(r.Body, *printJson)

	var reply v1.NewRecordReply
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

	// Verify record token signature.
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

func updateRecord() error {
	flags := flag.Args()[1:] // Chop off action.

	// Create New command
	challenge, err := util.Random(v1.ChallengeSize)
	if err != nil {
		return err
	}
	n := v1.UpdateUnvetted{
		Challenge: hex.EncodeToString(challenge),
	}

	// Fish out metadata records and filenames
	var tokenCount uint
	for _, v := range flags {
		switch {
		case regexAppendMD.MatchString(v):
			s := regexAppendMD.FindString(v)
			i, err := strconv.ParseUint(regexMDID.FindString(s),
				10, 64)
			if err != nil {
				return err
			}
			n.MDAppend = append(n.MDAppend, v1.MetadataStream{
				ID:      i,
				Payload: v[len(s):],
			})

		case regexOverwriteMD.MatchString(v):
			s := regexOverwriteMD.FindString(v)
			i, err := strconv.ParseUint(regexMDID.FindString(s),
				10, 64)
			if err != nil {
				return err
			}
			n.MDOverwrite = append(n.MDOverwrite, v1.MetadataStream{
				ID:      i,
				Payload: v[len(s):],
			})

		case regexFileAdd.MatchString(v):
			s := regexFileAdd.FindString(v)
			f, _, err := getFile(v[len(s):])
			if err != nil {
				return err
			}
			n.FilesAdd = append(n.FilesAdd, *f)

		case regexFileDel.MatchString(v):
			s := regexFileDel.FindString(v)
			n.FilesDel = append(n.FilesDel, v[len(s):])

		case regexToken.MatchString(v):
			if tokenCount != 0 {
				return fmt.Errorf("only 1 token allowed")
			}
			s := regexToken.FindString(v)
			n.Token = v[len(s):]
			tokenCount++

		default:
			return fmt.Errorf("invalid action %v", v)
		}
	}

	if tokenCount != 1 {
		return fmt.Errorf("must provide token")
	}

	// Fetch remote identity
	id, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	// Prety print
	if *verbose {
		fmt.Printf("Update record: %v\n", n.Token)
		if len(n.FilesAdd) > 0 {
			s := "  Files add         : "
			ss := strings.Repeat(" ", len(s))
			for i, v := range n.FilesAdd {
				fmt.Printf("%s%02v: %v %v %v\n",
					s, i, v.Digest, v.Name, v.MIME)
				s = ss
			}
		}
		if len(n.FilesDel) > 0 {
			s := "  Files delete      : "
			ss := strings.Repeat(" ", len(s))
			for _, v := range n.FilesDel {
				fmt.Printf("%s%v\n", s, v)
				s = ss
			}
		}
		if len(n.MDOverwrite) > 0 {
			s := "  Metadata overwrite: "
			for _, v := range n.MDOverwrite {
				fmt.Printf("%s%v", s, v.ID)
				s = ", "
			}
			fmt.Printf("\n")
		}
		if len(n.MDAppend) > 0 {
			s := "  Metadata append   : "
			for _, v := range n.MDAppend {
				fmt.Printf("%s%v", s, v.ID)
				s = ", "
			}
			fmt.Printf("\n")
		}
	}

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
	r, err := c.Post(*rpchost+v1.UpdateUnvettedRoute, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := getErrorFromResponse(r)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	bodyBytes := util.ConvertBodyToByteArray(r.Body, *printJson)

	var reply v1.UpdateUnvettedReply
	err = json.Unmarshal(bodyBytes, &reply)
	if err != nil {
		return fmt.Errorf("Could node unmarshal UpdateReply: %v", err)
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

	// XXX Verify merkle root.
	//hashes := make([]*[sha256.Size]byte, 0, len(flags[1:]))
	//if !bytes.Equal(merkle.Root(hashes)[:], root) {
	//	return fmt.Errorf("invalid merkle root")
	//}

	// Verify record token signature.
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
		e, err := getErrorFromResponse(r)
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
	if reply.Record.Status == v1.RecordStatusInvalid ||
		reply.Record.Status == v1.RecordStatusNotFound {
		// Pretty print record
		status, ok := v1.RecordStatus[reply.Record.Status]
		if !ok {
			status = v1.RecordStatus[v1.RecordStatusInvalid]
		}
		fmt.Printf("Record       : %v\n", flags[0])
		fmt.Printf("  Status     : %v\n", status)
		return nil
	}

	// Verify content
	err = v1.Verify(*id, reply.Record.CensorshipRecord,
		reply.Record.Files)
	if err != nil {
		return err
	}

	if !*printJson {
		printRecordRecord("Unvetted record", reply.Record)
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
		e, err := getErrorFromResponse(r)
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
	if reply.Record.Status == v1.RecordStatusInvalid ||
		reply.Record.Status == v1.RecordStatusNotFound {
		// Pretty print record
		status, ok := v1.RecordStatus[reply.Record.Status]
		if !ok {
			status = v1.RecordStatus[v1.RecordStatusInvalid]
		}
		fmt.Printf("Record     : %v\n", flags[0])
		fmt.Printf("  Status     : %v\n", status)
		return nil
	}

	// Verify content
	err = v1.Verify(*id, reply.Record.CensorshipRecord,
		reply.Record.Files)
	if err != nil {
		return err
	}

	if !*printJson {
		printRecordRecord("Vetted record", reply.Record)
	}
	return nil
}

func convertStatus(s string) (v1.RecordStatusT, error) {
	switch s {
	case "censor":
		return v1.RecordStatusCensored, nil
	case "publish":
		return v1.RecordStatusPublic, nil
	}

	return v1.RecordStatusInvalid, fmt.Errorf("invalid status")
}

func setUnvettedStatus() error {
	flags := flag.Args()[1:] // Chop off action.

	// Make sure we have the status and the censorship token
	if len(flags) < 2 {
		return fmt.Errorf("must at least provide status and " +
			"censorship token")
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

	// Optional metadata updates
	for _, v := range flags[2:] {
		switch {
		case regexAppendMD.MatchString(v):
			s := regexAppendMD.FindString(v)
			i, err := strconv.ParseUint(regexMDID.FindString(s),
				10, 64)
			if err != nil {
				return err
			}
			n.MDAppend = append(n.MDAppend, v1.MetadataStream{
				ID:      i,
				Payload: v[len(s):],
			})

		case regexOverwriteMD.MatchString(v):
			s := regexOverwriteMD.FindString(v)
			i, err := strconv.ParseUint(regexMDID.FindString(s),
				10, 64)
			if err != nil {
				return err
			}
			n.MDOverwrite = append(n.MDOverwrite, v1.MetadataStream{
				ID:      i,
				Payload: v[len(s):],
			})
		default:
			return fmt.Errorf("invalid metadata action %v", v)
		}
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
		e, err := getErrorFromResponse(r)
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
		// Pretty print record
		status, ok := v1.RecordStatus[reply.Status]
		if !ok {
			status = v1.RecordStatus[v1.RecordStatusInvalid]
		}
		fmt.Printf("Set record status:\n")
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
				return newRecord()
			case "identity":
				return getIdentity()
			case "plugin":
				return plugin()
			case "plugininventory":
				return getPluginInventory()
			case "inventory":
				return inventory()
			case "getunvetted":
				return getUnvetted()
			case "getvetted":
				return getVetted()
			case "setunvettedstatus":
				return setUnvettedStatus()
			case "update":
				return updateRecord()
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
