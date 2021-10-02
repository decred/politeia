// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/decred/dcrd/dcrutil/v3"
	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	v2 "github.com/decred/politeia/politeiad/api/v2"
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/util"
)

const allowInteractive = "i-know-this-is-a-bad-idea"

var (
	regexMD          = regexp.MustCompile(`^metadata:`)
	regexMDID        = regexp.MustCompile(`[a-z]{1,16}[\d]{1,2}:`)
	regexMDPluginID  = regexp.MustCompile(`[a-z]{1,16}`)
	regexMDStreamID  = regexp.MustCompile(`[\d]{1,2}`)
	regexAppendMD    = regexp.MustCompile(`^appendmetadata:`)
	regexOverwriteMD = regexp.MustCompile(`^overwritemetadata:`)
	regexFileAdd     = regexp.MustCompile(`^add:`)
	regexFileDel     = regexp.MustCompile(`^del:`)
	regexToken       = regexp.MustCompile(`^token:`)

	defaultHomeDir          = dcrutil.AppDataDir("politeia", false)
	defaultIdentityFilename = "identity.json"

	defaultPDAppDir    = dcrutil.AppDataDir("politeiad", false)
	defaultRPCCertFile = filepath.Join(defaultPDAppDir, "https.cert")

	identityFilename = flag.String("id", filepath.Join(defaultHomeDir,
		defaultIdentityFilename), "remote server identity file")
	testnet     = flag.Bool("testnet", false, "Use testnet port")
	verbose     = flag.Bool("v", false, "Verbose")
	rpcuser     = flag.String("rpcuser", "", "RPC user name for privileged calls")
	rpcpass     = flag.String("rpcpass", "", "RPC password for privileged calls")
	rpchost     = flag.String("rpchost", "", "RPC host")
	rpccert     = flag.String("rpccert", "", "RPC certificate")
	interactive = flag.String("interactive", "", "Set to "+
		allowInteractive+" to to turn off interactive mode during "+
		"identity fetch")
)

const availableCmds = `
Available commands:
  identity         Get server identity
  new              Submit new record
                   Args: [metadata:<id>:metadataJSON]... <filepaths>...
  verify           Verify record was accepted 
                   Args: <serverkey> <token> <signature> <filepaths>...
  edit             Edit record
                   Args: [actionMetadata:<id>:metadataJSON]... 
                         <actionfile:filename>... token:<token>
  editmetadata     Edit record metdata 
                   Args: [actionMetadata:<id>:metadataJSON]... token:<token>
  setstatus        Set record status 
                   Args: <token> <status>
  record           Get a record 
                   Args: <token>
  inventory        Get the record inventory 
                   Args (optional): <state> <status> <page>

Metadata actions: appendmetadata, overwritemetadata
File actions: add, del
Record statuses: public, censored, or archived

A metadata <id> consists of the <pluginID><streamID>. Plugin IDs are strings
and stream IDs are uint32. Below are example metadata arguments where the
plugin ID is 'testid' and the stream ID is '1'.

Submit new metadata: 'metadata:testid1:{"foo":"bar"}'
Append metadata    : 'appendmetadata:testid1:{"foo":"bar"}'
Overwrite metadata : 'overwritemetadata:testid1:{"foo":"bar"}'

`

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeia [flags] <action> [arguments]\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, availableCmds)
}

func printRecord(header string, r v2.Record) {
	// Pretty print record
	status, ok := v2.RecordStatuses[r.Status]
	if !ok {
		status = v2.RecordStatuses[v2.RecordStatusInvalid]
	}
	fmt.Printf("%v:\n", header)
	fmt.Printf("  Status     : %v\n", status)
	fmt.Printf("  Timestamp  : %v\n", time.Unix(r.Timestamp, 0).UTC())
	fmt.Printf("  Version    : %v\n", r.Version)
	fmt.Printf("  Censorship record:\n")
	fmt.Printf("    Merkle   : %v\n", r.CensorshipRecord.Merkle)
	fmt.Printf("    Token    : %v\n", r.CensorshipRecord.Token)
	fmt.Printf("    Signature: %v\n", r.CensorshipRecord.Signature)
	for k, v := range r.Files {
		fmt.Printf("  File (%02v)  :\n", k)
		fmt.Printf("    Name     : %v\n", v.Name)
		fmt.Printf("    MIME     : %v\n", v.MIME)
		fmt.Printf("    Digest   : %v\n", v.Digest)
	}
	for _, v := range r.Metadata {
		fmt.Printf("  Metadata stream %v %02v:\n", v.PluginID, v.StreamID)
		fmt.Printf("    %v\n", v.Payload)
	}
}

// parseMetadataIDs parses and returns the plugin ID and stream ID from a full
// metadata ID string. See the example below.
//
// Metadata ID string: "pluginid12:"
// Plugin ID: "plugindid"
// Stream ID: 12
func parseMetadataIDs(mdID string) (string, uint32, error) {
	// Parse the plugin ID. This is the "pluginid" part of the
	// "pluginid12:" metadata ID.
	pluginID := regexMDPluginID.FindString(mdID)

	// Parse the stream ID. This is the "12" part of the
	// "pluginid12:" metadata ID.
	streamID, err := strconv.ParseUint(regexMDStreamID.FindString(mdID),
		10, 64)
	if err != nil {
		return "", 0, err
	}

	return pluginID, uint32(streamID), nil
}

// parseMetadata returns the metadata streams for all metadata flags.
func parseMetadata(flags []string) ([]v2.MetadataStream, error) {
	md := make([]v2.MetadataStream, 0, len(flags))
	for _, v := range flags {
		// Example metadata: 'metadata:pluginid12:{"moo":"lala"}'

		// Parse metadata tag. This is the 'metadata:' part of the
		// example metadata.
		mdTag := regexMD.FindString(v)
		if mdTag == "" {
			// This is not metadata
			continue
		}

		// Parse the full metatdata ID string. This is the "pluginid12:"
		// part of the example metadata.
		mdID := regexMDID.FindString(v)

		// Parse the plugin ID and stream ID
		pluginID, streamID, err := parseMetadataIDs(mdID)
		if err != nil {
			return nil, err
		}

		md = append(md, v2.MetadataStream{
			PluginID: pluginID,
			StreamID: streamID,
			Payload:  v[len(mdTag)+len(mdID):],
		})
	}

	return md, nil
}

// parseMetadata returns the metadata streams for all appendmetadata flags.
func parseMetadataAppend(flags []string) ([]v2.MetadataStream, error) {
	md := make([]v2.MetadataStream, 0, len(flags))
	for _, v := range flags {
		// Example metadata: 'appendmetadata:pluginid12:{"moo":"lala"}'

		// Parse append metadata tag. This is the 'appendmetadata:' part
		// of the example metadata.
		appendTag := regexAppendMD.FindString(v)
		if appendTag == "" {
			// This is not a metadata append
			continue
		}

		// Parse the full metatdata ID string. This is the "pluginid12:"
		// part of the example metadata.
		mdID := regexMDID.FindString(v)

		// Parse the plugin ID and stream ID
		pluginID, streamID, err := parseMetadataIDs(mdID)
		if err != nil {
			return nil, err
		}

		md = append(md, v2.MetadataStream{
			PluginID: pluginID,
			StreamID: streamID,
			Payload:  v[len(appendTag)+len(mdID):],
		})
	}

	return md, nil
}

// parseMetadata returns the metadata streams for all overwritemetadata flags.
func parseMetadataOverwrite(flags []string) ([]v2.MetadataStream, error) {
	md := make([]v2.MetadataStream, 0, len(flags))
	for _, v := range flags {
		// Example metadata: 'overwritemetadata:pluginid12:{"moo":"lala"}'

		// Parse overwrite metadata tag. This is the 'overwritemetadata:'
		// part of the example metadata.
		overwriteTag := regexOverwriteMD.FindString(v)
		if overwriteTag == "" {
			// This is not a metadata overwrite
			continue
		}

		// Parse the full metatdata ID string. This is the "pluginid12:"
		// part of the example metadata.
		mdID := regexMDID.FindString(v)

		// Parse the plugin ID and stream ID
		pluginID, streamID, err := parseMetadataIDs(mdID)
		if err != nil {
			return nil, err
		}

		md = append(md, v2.MetadataStream{
			PluginID: pluginID,
			StreamID: streamID,
			Payload:  v[len(overwriteTag)+len(mdID):],
		})
	}

	return md, nil
}

// parseFiles returns the files for all filename flags.
func parseFiles(flags []string) ([]v2.File, error) {
	// Parse file names from flags
	filenames := make([]string, 0, len(flags))
	for _, v := range flags {
		if regexMD.FindString(v) != "" {
			// This is metadata, not a filename
			continue
		}

		// This is a filename
		filenames = append(filenames, v)
	}
	if len(filenames) == 0 {
		return nil, fmt.Errorf("no filenames provided")
	}

	// Read files from disk
	files := make([]v2.File, 0, len(filenames))
	for _, v := range filenames {
		f, _, err := getFile(v)
		if err != nil {
			return nil, err
		}
		files = append(files, *f)
	}

	return files, nil

}

// parseFileAdds returns the files for all file add flags.
func parseFileAdds(flags []string) ([]v2.File, error) {
	// Parse file names from flags
	filenames := make([]string, 0, len(flags))
	for _, v := range flags {
		fileAddTag := regexFileAdd.FindString(v)
		if fileAddTag == "" {
			// This is not a file add flag
			continue
		}

		// This is a filename
		filenames = append(filenames, v[len(fileAddTag):])
	}

	// Read files from disk
	files := make([]v2.File, 0, len(filenames))
	for _, v := range filenames {
		f, _, err := getFile(v)
		if err != nil {
			return nil, err
		}
		files = append(files, *f)
	}

	return files, nil
}

// parseFileDels returns the filenames for all file del flags.
func parseFileDels(flags []string) []string {
	// Parse file names from flags
	filenames := make([]string, 0, len(flags))
	for _, v := range flags {
		fileDelTag := regexFileDel.FindString(v)
		if fileDelTag == "" {
			// This is not a file del flag
			continue
		}

		// This is a filename
		filenames = append(filenames, v[len(fileDelTag):])
	}
	return filenames
}

// parseToken returns the token from the flags.
func parseToken(flags []string) string {
	var token string
	for _, v := range flags {
		tokenTag := regexToken.FindString(v)
		if tokenTag == "" {
			// This is not the token
			continue
		}
		token = v[len(tokenTag):]
	}
	return token
}

// decodeToken decodes the provided token string into a byte slice. The token
// must be a full length politeiad v2 token.
func decodeToken(t string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTstore, t)
}

func convertStatus(s string) v2.RecordStatusT {
	switch s {
	case "unreviewed":
		return v2.RecordStatusUnreviewed
	case "public":
		return v2.RecordStatusPublic
	case "censored":
		return v2.RecordStatusCensored
	case "archived":
		return v2.RecordStatusArchived
	}
	return v2.RecordStatusInvalid
}

func convertState(s string) v2.RecordStateT {
	switch s {
	case "unvetted":
		return v2.RecordStateUnvetted
	case "vetted":
		return v2.RecordStateVetted
	}
	return v2.RecordStateInvalid
}

func getFile(filename string) (*v2.File, *[sha256.Size]byte, error) {
	var err error

	filename = util.CleanAndExpandPath(filename)
	file := &v2.File{
		Name: filepath.Base(filename),
	}
	file.MIME, file.Digest, file.Payload, err = util.LoadFile(filename)
	if err != nil {
		return nil, nil, err
	}
	if !mime.MimeValid(file.MIME) {
		return nil, nil, fmt.Errorf("unsupported mime type '%v' "+
			"for file '%v'", file.MIME, filename)
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

// getIdentity retrieves the politeiad server identity, i.e. public key.
func getIdentity() error {
	// Fetch remote identity
	c, err := pdclient.New(*rpchost, *rpccert, *rpcuser, *rpcpass, nil)
	if err != nil {
		return err
	}
	id, err := c.Identity(context.Background())
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
	rf = util.CleanAndExpandPath(rf)

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

// recordNew submits a new record to the politeiad v2 API.
func recordNew() error {
	flags := flag.Args()[1:] // Chop off action.

	// Parse metadata and files
	metadata, err := parseMetadata(flags)
	if err != nil {
		return err
	}
	files, err := parseFiles(flags)
	if err != nil {
		return err
	}

	// Load server identity
	pid, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	// Setup client
	c, err := pdclient.New(*rpchost, *rpccert, *rpcuser, *rpcpass, pid)
	if err != nil {
		return err
	}

	// Submit record
	r, err := c.RecordNew(context.Background(), metadata, files)
	if err != nil {
		return err
	}

	if *verbose {
		printRecord("Record submitted", *r)
		fmt.Printf("Server public key: %v\n", pid.String())
	}

	// Verify record
	return pdclient.RecordVerify(*r, pid.String())
}

// recordVerify verifies that a record was submitted by verifying the
// censorship record signature.
func recordVerify() error {
	flags := flag.Args()[1:] // Chop off action.
	if len(flags) < 3 {
		return fmt.Errorf("arguments are missing")
	}

	// Unpack args
	var (
		serverKey = flags[0]
		token     = flags[1]
		signature = flags[2]
	)

	// Parse files
	files, err := parseFiles(flags[3:])
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no files found")
	}

	// Calc merkle root of files
	digests := make([]string, 0, len(files))
	for _, v := range files {
		digests = append(digests, v.Digest)
	}
	mr, err := util.MerkleRoot(digests)
	if err != nil {
		return err
	}
	merkle := hex.EncodeToString(mr[:])

	// Load identity
	pid, err := identity.PublicIdentityFromString(serverKey)
	if err != nil {
		return err
	}

	// Verify record
	r := v2.Record{
		Files: files,
		CensorshipRecord: v2.CensorshipRecord{
			Token:     token,
			Merkle:    merkle,
			Signature: signature,
		},
	}
	err = pdclient.RecordVerify(r, pid.String())
	if err != nil {
		return err
	}

	fmt.Printf("Server key : %s\n", serverKey)
	fmt.Printf("Token      : %s\n", token)
	fmt.Printf("Merkle root: %s\n", merkle)
	fmt.Printf("Signature  : %s\n\n", signature)
	fmt.Println("Record successfully verified")

	return nil
}

// recordEdit edits an existing record.
func recordEdit() error {
	flags := flag.Args()[1:] // Chop off action.

	// Parse args
	mdAppend, err := parseMetadataAppend(flags)
	if err != nil {
		return err
	}
	mdOverwrite, err := parseMetadataOverwrite(flags)
	if err != nil {
		return err
	}
	fileAdds, err := parseFileAdds(flags)
	if err != nil {
		return err
	}
	fileDels := parseFileDels(flags)
	token := parseToken(flags)
	if token == "" {
		return fmt.Errorf("must provide token")
	}

	// Load server identity
	pid, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	// Setup client
	c, err := pdclient.New(*rpchost, *rpccert, *rpcuser, *rpcpass, pid)
	if err != nil {
		return err
	}

	// Edit record
	r, err := c.RecordEdit(context.Background(), token,
		mdAppend, mdOverwrite, fileAdds, fileDels)
	if err != nil {
		return err
	}

	if *verbose {
		printRecord("Record updated", *r)
		fmt.Printf("Server public key: %v\n", pid.String())
	}

	// Verify record
	return pdclient.RecordVerify(*r, pid.String())
}

// recordEditMetadata edits the metadata of a record.
func recordEditMetadata() error {
	flags := flag.Args()[1:] // Chop off action.

	// Parse args
	mdAppend, err := parseMetadataAppend(flags)
	if err != nil {
		return err
	}
	mdOverwrite, err := parseMetadataOverwrite(flags)
	if err != nil {
		return err
	}
	token := parseToken(flags)
	if token == "" {
		return fmt.Errorf("must provide token")
	}

	// Load server identity
	pid, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	// Setup client
	c, err := pdclient.New(*rpchost, *rpccert, *rpcuser, *rpcpass, pid)
	if err != nil {
		return err
	}

	// Edit record metadata
	r, err := c.RecordEditMetadata(context.Background(),
		token, mdAppend, mdOverwrite)
	if err != nil {
		return err
	}

	if *verbose {
		printRecord("Record metadata updated", *r)
		fmt.Printf("Server public key: %v\n", pid.String())
	}

	// Verify record
	return pdclient.RecordVerify(*r, pid.String())
}

// recordSetStatus sets the status of a record.
func recordSetStatus() error {
	flags := flag.Args()[1:]

	// Make sure we have the status and the censorship token
	if len(flags) < 2 {
		return fmt.Errorf("must at least provide status and " +
			"censorship token")
	}

	// Validate censorship token
	token := flags[0]
	_, err := decodeToken(token)
	if err != nil {
		return err
	}

	// Validate status
	status := convertStatus(flags[1])
	if status == v2.RecordStatusInvalid {
		return fmt.Errorf("invalid status")
	}

	// Load server identity
	pid, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	// Setup client
	c, err := pdclient.New(*rpchost, *rpccert, *rpcuser, *rpcpass, pid)
	if err != nil {
		return err
	}

	// Set record status
	r, err := c.RecordSetStatus(context.Background(),
		token, status, nil, nil)
	if err != nil {
		return err
	}

	if *verbose {
		printRecord("Record status updated", *r)
		fmt.Printf("Server public key: %v\n", pid.String())
	}

	// Verify record
	return pdclient.RecordVerify(*r, pid.String())
}

// record retreives a record.
func record() error {
	flags := flag.Args()[1:] // Chop off action.

	// Make sure we have the censorship token
	if len(flags) != 1 {
		return fmt.Errorf("must provide one and only one censorship " +
			"token")
	}

	// Validate censorship token
	token := flags[0]
	_, err := decodeToken(token)
	if err != nil {
		return err
	}

	// Load server identity
	pid, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	// Setup client
	c, err := pdclient.New(*rpchost, *rpccert, *rpcuser, *rpcpass, pid)
	if err != nil {
		return err
	}

	// Set record status
	reqs := []v2.RecordRequest{
		{
			Token: token,
		},
	}
	records, err := c.Records(context.Background(), reqs)
	if err != nil {
		return err
	}
	r, ok := records[token]
	if !ok {
		return fmt.Errorf("record not found")
	}

	if *verbose {
		printRecord("Record", r)
		fmt.Printf("Server public key: %v\n", pid.String())
	}

	// Verify record
	return pdclient.RecordVerify(r, pid.String())
}

// recordInventory retrieves the censorship record tokens of the records in
// the inventory, categorized by their record state and record status.
func recordInventory() error {
	flags := flag.Args()[1:] // Chop off action.

	// Either the state, status and page number must all be given or
	// none should be given at all.
	if len(flags) > 0 && len(flags) != 3 {
		return fmt.Errorf("invalid number of arguments (%v); you can "+
			"either provide a state, status, and page number or you can "+
			"provide no arguments at all", len(flags))
	}

	// Unpack args
	var (
		state      v2.RecordStateT
		status     v2.RecordStatusT
		pageNumber uint32
	)
	if len(flags) == 3 {
		state = convertState(flags[0])
		status = convertStatus(flags[1])
		u, err := strconv.ParseUint(flags[2], 10, 64)
		if err != nil {
			return fmt.Errorf("unable to parse page number '%v': %v",
				flags[2], err)
		}
		pageNumber = uint32(u)
	}

	// Load server identity
	pid, err := identity.LoadPublicIdentity(*identityFilename)
	if err != nil {
		return err
	}

	// Setup client
	c, err := pdclient.New(*rpchost, *rpccert, *rpcuser, *rpcpass, pid)
	if err != nil {
		return err
	}

	// Get inventory
	ir, err := c.Inventory(context.Background(), state, status, pageNumber)
	if err != nil {
		return err
	}

	if *verbose {
		if len(ir.Unvetted) > 0 {
			fmt.Printf("Unvetted\n")
			fmt.Printf("%v\n", util.FormatJSON(ir.Unvetted))
		}
		if len(ir.Vetted) > 0 {
			fmt.Printf("Vetted\n")
			fmt.Printf("%v\n", util.FormatJSON(ir.Vetted))
		}
	}

	return nil
}

func _main() error {
	flag.Usage = usage
	flag.Parse()
	if len(flag.Args()) == 0 {
		usage()
		return fmt.Errorf("must provide action")
	}

	// Setup RPC host
	if *rpchost == "" {
		if *testnet {
			*rpchost = v1.DefaultTestnetHost
		} else {
			*rpchost = v1.DefaultMainnetHost
		}
	}
	port := v1.DefaultMainnetPort
	if *testnet {
		port = v1.DefaultTestnetPort
	}
	*rpchost = util.NormalizeAddress(*rpchost, port)
	u, err := url.Parse("https://" + *rpchost)
	if err != nil {
		return err
	}
	*rpchost = u.String()

	// Setup RPC cert
	if *rpccert == "" {
		*rpccert = defaultRPCCertFile
	}

	// Scan through command line arguments.
	for i, a := range flag.Args() {
		// Select action
		if i == 0 {
			switch a {
			case "identity":
				return getIdentity()
			case "new":
				return recordNew()
			case "verify":
				return recordVerify()
			case "edit":
				return recordEdit()
			case "editmetadata":
				return recordEditMetadata()
			case "setstatus":
				return recordSetStatus()
			case "record":
				return record()
			case "inventory":
				return recordInventory()
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
