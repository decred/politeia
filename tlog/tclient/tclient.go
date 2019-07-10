package main

import (
	"bufio"
	"bytes"
	"crypto"
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/dcrutil"
	dcrtime "github.com/decred/dcrtime/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/tlog/api/v1"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/der"
	_ "github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
)

var (
	// Server defaults
	defaultHomeDir       = dcrutil.AppDataDir("tclient", false)
	defaultHTTPSCertFile = filepath.Join(defaultHomeDir, "https.cert")

	rpcuser           = flag.String("rpcuser", "", "RPC user name for privileged calls")
	rpcpass           = flag.String("rpcpass", "", "RPC password for privileged calls")
	rpchost           = flag.String("rpchost", "127.0.0.1", "RPC host")
	rpccert           = flag.String("rpccert", defaultHTTPSCertFile, "RPC certificate")
	testnet           = flag.Bool("testnet", false, "Use testnet port")
	printJson         = flag.Bool("json", false, "Print JSON")
	identityFilename  = flag.String("identity", filepath.Join(defaultHomeDir, "identity.bin"), "Client identity")
	publicKeyFilename = flag.String("publickey", filepath.Join(defaultHomeDir, "server.der"), "Server identity")

	verify = false // Don't validate server TLS certificate

	myID      *identity.FullIdentity // our identity
	publicKey crypto.PublicKey       // remote server signing key
)

// getErrorFromResponse extracts a user-readable string from the response from
// politeiad, which will contain a JSON error.
func getErrorFromResponse(r *http.Response) (string, error) {
	var errMsg string
	decoder := json.NewDecoder(r.Body)
	if r.StatusCode == http.StatusInternalServerError {
		var e v1.ErrorReply
		if err := decoder.Decode(&e); err != nil {
			return "", err
		}
		errMsg = fmt.Sprintf("%v", e.ErrorCode)
	} else {
		var e v1.UserError
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

func usage() {
	fmt.Fprintf(os.Stderr, "usage: tclient [flags] <action> [arguments]\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n actions:\n")
	// XXX fix doco
	//fmt.Fprintf(os.Stderr, "  newtree           - create new tree"+
	//	"\n")
	//fmt.Fprintf(os.Stderr, "\n actions:\n")
	//fmt.Fprintf(os.Stderr, "  append            - append file to tree "+
	//	"<treeid> <filename>\n")
	//fmt.Fprintf(os.Stderr, "  recordget         - retrieve record "+
	//	"<treeid> <recordid>\n")

	//fmt.Fprintf(os.Stderr, "  plugins           - Retrieve plugin "+
	//	"inventory\n")
	//fmt.Fprintf(os.Stderr, "  inventory         - Inventory records "+
	//	"<vetted count> <branches count>\n")
	//fmt.Fprintf(os.Stderr, "  new               - Create new record "+
	//	"[metadata<id>]... <filename>...\n")
	//fmt.Fprintf(os.Stderr, "  getunvetted       - Retrieve record "+
	//	"<id>\n")
	//fmt.Fprintf(os.Stderr, "  setunvettedstatus - Set unvetted record "+
	//	"status <publish|censor> <id> [actionmdid:metadata]...\n")
	//fmt.Fprintf(os.Stderr, "  updateunvetted    - Update unvetted record "+
	//	"[actionmdid:metadata]... <actionfile:filename>... "+
	//	"token:<token>\n")
	//fmt.Fprintf(os.Stderr, "  updatevetted      - Update vetted record "+
	//	"[actionmdid:metadata]... <actionfile:filename>... "+
	//	"token:<token>\n")
	//fmt.Fprintf(os.Stderr, "  updatevettedmd    - Update vetted record "+
	//	"metadata [actionmdid:metadata]... token:<token>\n")
	//fmt.Fprintf(os.Stderr, "\n")
	//fmt.Fprintf(os.Stderr, " metadata<id> is the word metadata followed "+
	//	"by digits. Example with 2 metadata records "+
	//	"metadata0:{\"moo\":\"12\",\"blah\":\"baz\"} "+
	//	"metadata1:{\"lala\":42}\n")
	//fmt.Fprintf(os.Stderr, " actionmdid is an action + metadatastream id "+
	//	"E.g. appendmetadata0:{\"foo\":\"bar\"} or "+
	//	"overwritemetadata12:{\"bleh\":\"truff\"}\n")

	fmt.Fprintf(os.Stderr, "\n")
}

// handleFile returns hash, signature of the string hash and data as strings to
// send to server.
func handleFile(filename string) (*v1.RecordEntry, error) {
	mime, data, err := util.LoadFile2(filename)
	if err != nil {
		return nil, err
	}

	// Encode data descriptor
	dd, err := json.Marshal(v1.DataDescriptor{
		Type:       v1.DataTypeMime,
		Descriptor: mime,
	})
	if err != nil {
		return nil, err
	}

	re := util.RecordEntryNew(myID, dd, data)
	return &re, nil
}

func handleError(r *http.Response) error {
	if r.StatusCode != http.StatusOK {
		e, err := getErrorFromResponse(r)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}
	return nil
}

func printTree(tree trillian.Tree) {
	fmt.Printf("TreeId            : %v\n", tree.TreeId)
	fmt.Printf("TreeState         : %v\n", tree.TreeState)
	fmt.Printf("TreeType          : %v\n", tree.TreeType)
	fmt.Printf("HashStrategy      : %v\n", tree.HashStrategy)
	fmt.Printf("HashAlgorithm     : %v\n", tree.HashAlgorithm)
	fmt.Printf("SignatureAlgorithm: %v\n", tree.SignatureAlgorithm)
	fmt.Printf("DisplayName       : %v\n", tree.DisplayName)
	fmt.Printf("Description       : %v\n", tree.Description)
	fmt.Printf("PublicKey         : %v\n", tree.PublicKey)
	fmt.Printf("MaxRootDuration   : %v\n", tree.MaxRootDuration)
	fmt.Printf("CreateTime        : %v\n", tree.CreateTime)
	fmt.Printf("UpdateTime        : %v\n", tree.UpdateTime)
	fmt.Printf("Deleted           : %v\n", tree.Deleted)
	fmt.Printf("DeleteTime        : %v\n", tree.DeleteTime)
}

func printRoot(root trillian.SignedLogRoot) {
	fmt.Printf("KeyHint         : %x\n", root.KeyHint)
	fmt.Printf("LogRoot         : %x\n", root.LogRoot)
	fmt.Printf("LogRootSignature: %x\n", root.LogRootSignature)

}

func printLogRootV1(l types.LogRootV1) {
	fmt.Printf("TreeSize      : %v\n", l.TreeSize)
	fmt.Printf("RootHash      : %x\n", l.RootHash)
	fmt.Printf("TimestampNanos: %v\n", l.TimestampNanos)
	fmt.Printf("Revision      : %v\n", l.Revision)
	fmt.Printf("Metadata      : %x\n", l.Metadata)
}

func printLeaf(leaf trillian.LogLeaf) {
	fmt.Printf("MerkleLeafHash    : %x\n", leaf.MerkleLeafHash)
	fmt.Printf("LeafValue         : %x\n", leaf.LeafValue)
	fmt.Printf("ExtraData         : %s\n", leaf.ExtraData)
	fmt.Printf("LeafIndex         : %v\n", leaf.LeafIndex)
	fmt.Printf("LeafIdentityHash  : %x\n", leaf.LeafIdentityHash)
	fmt.Printf("QueueTimestamp    : %v\n", leaf.QueueTimestamp)
	fmt.Printf("IntegrateTimestamp: %v\n", leaf.IntegrateTimestamp)
}

func printQueuedLeaf(ql trillian.QueuedLogLeaf) {
	printLeaf(*ql.Leaf)
	fmt.Printf("Status            : %v\n", ql.Status)
}

func printRecordEntry(r v1.RecordEntry) {
	fmt.Printf("PublicKey: %v\n", r.PublicKey)
	fmt.Printf("Hash     : %v\n", r.Hash)
	fmt.Printf("Signature: %v\n", r.Signature)
	fmt.Printf("DataHint : %v\n", r.DataHint)
	data, err := base64.StdEncoding.DecodeString(r.Data)
	if err != nil {
		panic(err) // for now
	}
	if len(data) > 40 {
		fmt.Printf("Data     : ...\n")
	} else {
		fmt.Printf("Data     : %s\n", data) // Assume string for now
	}
}

func printProof(p trillian.Proof) {
	fmt.Printf("LeafIndex: %v\n", p.LeafIndex)
	for k, v := range p.Hashes {
		fmt.Printf("Hash(%3v): %x\n", k, v)
	}
}

func printAnchor(a dcrtime.ChainInformation) {
	fmt.Printf("Timestamp : %v\n", a.ChainTimestamp)
	fmt.Printf("Tx        : %v\n", a.Transaction)
	fmt.Printf("MerkleRoot: %v\n", a.MerkleRoot)
	for k, v := range a.MerklePath.Hashes {
		fmt.Printf("Hash(%3v) : %x\n", k, v)
	}
}

func list() error {
	// convert to JSON and sent it to server
	b, err := json.Marshal(v1.List{})
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
	r, err := c.Post(*rpchost+v1.RouteList, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	err = handleError(r)
	if err != nil {
		return err
	}

	body := util.ConvertBodyToByteArray(r.Body, *printJson)
	var lr v1.ListReply
	err = json.Unmarshal(body, &lr)
	if err != nil {
		return fmt.Errorf("Could no unmarshal ListReply: %v", err)
	}

	if !*printJson {
		for _, v := range lr.Trees {
			fmt.Printf("\n")
			printTree(*v)
		}
	}

	return nil
}

func getPublicKey() error {
	// Make sure we won't overwrite the key file
	pkf := util.CleanAndExpandPath(*publicKeyFilename)
	if util.FileExists(pkf) {
		return fmt.Errorf("public key file already exists")
	}

	// convert to JSON and sent it to server
	b, err := json.Marshal(v1.PublicKey{})
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
	r, err := c.Post(*rpchost+v1.RoutePublicKey, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	err = handleError(r)
	if err != nil {
		return err
	}

	body := util.ConvertBodyToByteArray(r.Body, *printJson)
	var pkr v1.PublicKeyReply
	err = json.Unmarshal(body, &pkr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal PublicKeyReply: %v", err)
	}

	keyb, err := base64.StdEncoding.DecodeString(pkr.SigningKey)
	if err != nil {
		return err
	}
	publicKey, err = der.UnmarshalPublicKey(keyb)
	if err != nil {
		return err
	}

	// Save?
	spew.Dump(publicKey)
	fmt.Printf("\nSave to %v or ctrl-c to abort ", pkf)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if err = scanner.Err(); err != nil {
		return err
	}
	if len(scanner.Text()) != 0 {
		pkf = scanner.Text()
	}

	// Save public key
	err = ioutil.WriteFile(pkf, keyb, 0600)
	if err != nil {
		return err
	}

	return nil
}

func recordParse(index int) ([]v1.RecordEntry, error) {
	flags := flag.Args()[index:] // Chop off action.
	if len(flags) == 0 {
		return nil, fmt.Errorf("not enough arguments, expected " +
			"[key=value]... <filename>...")
	}

	re := make([]v1.RecordEntry, 0, len(flags))
	for _, v := range flags {
		// See if we are key value or a filename
		_, err := os.Stat(v)
		if err != nil {
			// maybe key value
			if !strings.Contains(v, "=") {
				return nil, err
			}
			// parse key=value
			a := strings.SplitN(v, "=", 2)
			if len(a) != 2 {
				return nil, fmt.Errorf("not a valid "+
					"'key=value': %v", v)
			}

			// Encode data descriptor
			dd, err := json.Marshal(v1.DataDescriptor{
				Type: v1.DataTypeKeyValue,
			})
			if err != nil {
				return nil, err
			}
			// Encode data
			kv, err := json.Marshal(v1.DataKeyValue{
				Key:   a[0],
				Value: a[1],
			})
			if err != nil {
				return nil, err
			}
			re = append(re, util.RecordEntryNew(myID, dd, kv))
			continue
		}
		r, err := handleFile(v)
		if err != nil {
			return nil, err
		}
		re = append(re, *r)
	}

	return re, nil
}

func recordNew() error {
	re, err := recordParse(1)
	if err != nil {
		return err
	}
	rn := v1.RecordNew{RecordEntries: re}

	// convert to JSON and sent it to server
	b, err := json.Marshal(rn)
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
	r, err := c.Post(*rpchost+v1.RouteRecordNew, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	err = handleError(r)
	if err != nil {
		return err
	}

	body := util.ConvertBodyToByteArray(r.Body, *printJson)
	var rnr v1.RecordNewReply
	err = json.Unmarshal(body, &rnr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal RecordNewReply: %v", err)
	}

	// Let's verify what came back
	verifier, err := client.NewLogVerifierFromTree(&rnr.Tree)
	if err != nil {
		return err
	}
	lrInitial, err := tcrypto.VerifySignedLogRoot(verifier.PubKey,
		crypto.SHA256, &rnr.InitialRoot)
	if err != nil {
		return err
	}
	lrSTH, err := tcrypto.VerifySignedLogRoot(verifier.PubKey,
		crypto.SHA256, &rnr.STH)
	if err != nil {
		return err
	}
	for _, v := range rnr.Proofs {
		err := util.QueuedLeafProofVerify(publicKey, lrSTH, v)
		if err != nil {
			return err
		}
	}

	if !*printJson {
		fmt.Printf("\nTree:\n")
		printTree(rnr.Tree)

		fmt.Printf("\nInitial root:\n")
		printRoot(rnr.InitialRoot)
		fmt.Printf("\nInitial root LogRootV1:\n")
		printLogRootV1(*lrInitial)

		fmt.Printf("\nSTH:\n")
		printRoot(rnr.STH)
		fmt.Printf("\nSTH LogRootV1:\n")
		printLogRootV1(*lrSTH)

		fmt.Printf("\n")
		for _, v := range rnr.Proofs {
			printQueuedLeaf(v.QueuedLeaf)
			fmt.Printf("\n")
		}
	}

	return nil
}

func recordAppend() error {
	// get tree id
	flags := flag.Args()[1:] // Chop off action.
	if len(flags) < 2 {
		return fmt.Errorf("not enough arguments, expected " +
			"<recordid> [key=value]... <filename>...")
	}
	id, err := strconv.ParseInt(flags[0], 10, 64)
	if err != nil {
		return err
	}

	re, err := recordParse(2)
	if err != nil {
		return err
	}
	ra := v1.RecordAppend{
		Id:            id,
		RecordEntries: re,
	}

	// convert to JSON and sent it to server
	b, err := json.Marshal(ra)
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
	r, err := c.Post(*rpchost+v1.RouteRecordAppend, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	err = handleError(r)
	if err != nil {
		return err
	}

	body := util.ConvertBodyToByteArray(r.Body, *printJson)
	var rar v1.RecordAppendReply
	err = json.Unmarshal(body, &rar)
	if err != nil {
		return fmt.Errorf("Could not unmarshal RecordAppendReply: %v",
			err)
	}

	// Let's verify what came back
	lrv1, err := tcrypto.VerifySignedLogRoot(publicKey,
		crypto.SHA256, &rar.STH)
	if err != nil {
		return fmt.Errorf("VerifySignedLogRoot: %v", err)
	}
	for _, v := range rar.Proofs {
		err := util.QueuedLeafProofVerify(publicKey, lrv1, v)
		if err != nil {
			return err
		}
	}

	// XXX fix printing
	if !*printJson {
		fmt.Printf("\nSTH:\n")
		printRoot(rar.STH)
		//fmt.Printf("\nSTH LogRootV1:\n")
		//printLogRootV1(*lrSTH)

		fmt.Printf("\n")
		for _, v := range rar.Proofs {
			printQueuedLeaf(v.QueuedLeaf)
			fmt.Printf("\n")
		}
	}

	return nil
}

func recordGet() error {
	flags := flag.Args()[1:] // Chop off action.
	if len(flags) != 1 {
		return fmt.Errorf("not enough arguments, expected " +
			"<id>")
	}

	id, err := strconv.ParseInt(flags[0], 10, 64)
	if err != nil {
		return err
	}

	// convert to JSON and sent it to server
	b, err := json.Marshal(v1.RecordGet{Id: id})
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
	r, err := c.Post(*rpchost+v1.RouteRecordGet, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	err = handleError(r)
	if err != nil {
		return err
	}

	body := util.ConvertBodyToByteArray(r.Body, *printJson)
	var rgr v1.RecordGetReply
	err = json.Unmarshal(body, &rgr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal RecordGetReply: %v", err)
	}

	// Verify STH
	_, err = tcrypto.VerifySignedLogRoot(publicKey, crypto.SHA256,
		&rgr.STH)
	if err != nil {
		return err
	}

	// Verify record entry proofs
	for _, v := range rgr.Proofs {
		err := util.RecordEntryProofVerify(publicKey, v)
		if err != nil {
			return err
		}
	}

	if !*printJson {
		fmt.Printf("\nSTH:\n")
		printRoot(rgr.STH)
		fmt.Printf("\nLeaves:\n")

		// XXX fix printing
		for _, v := range rgr.Proofs {
			printLeaf(*v.Leaf)
			fmt.Printf("\n")
		}

		fmt.Printf("\nRecords:\n")
		for _, v := range rgr.Proofs {
			printRecordEntry(*v.RecordEntry)
			fmt.Printf("\n")
		}
	}

	return nil
}

func recordEntriesGet() error {
	flags := flag.Args()[1:] // Chop off action.
	if len(flags) == 0 {
		return fmt.Errorf("not enough arguments, expected " +
			"<id,merklehash>...")
	}

	reg := v1.RecordEntriesGet{
		Entries: make([]v1.RecordEntryIdentifier, 0, len(flags)),
	}
	for _, v := range flags {
		a := strings.SplitN(v, ",", 2)
		if len(a) != 2 {
			return fmt.Errorf("invalid format, expected: " +
				"id,merklehash")
		}
		id, err := strconv.ParseInt(a[0], 10, 64)
		if err != nil {
			return err
		}
		if !util.IsDigest(a[1]) {
			return fmt.Errorf("invalid hash: %v", a[1])
		}
		reg.Entries = append(reg.Entries, v1.RecordEntryIdentifier{
			Id:         id,
			MerkleHash: a[1],
		})
	}

	// convert to JSON and sent it to server
	b, err := json.Marshal(reg)
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
	r, err := c.Post(*rpchost+v1.RouteRecordEntriesGet, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	err = handleError(r)
	if err != nil {
		return err
	}

	body := util.ConvertBodyToByteArray(r.Body, *printJson)
	var rgr v1.RecordEntriesGetReply
	err = json.Unmarshal(body, &rgr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal RecordEntriesGetReply: %v", err)
	}

	// Verify record entry proofs
	for _, v := range rgr.Proofs {
		err := util.RecordEntryProofVerify(publicKey, v)
		if err != nil {
			return err
		}
	}

	return nil
}

func recordFsck() error {
	flags := flag.Args()[1:] // Chop off action.
	if len(flags) != 1 {
		return fmt.Errorf("not enough arguments, expected " +
			"<id>")
	}

	id, err := strconv.ParseInt(flags[0], 10, 64)
	if err != nil {
		return err
	}

	// convert to JSON and sent it to server
	b, err := json.Marshal(v1.RecordFsck{Id: id})
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
	r, err := c.Post(*rpchost+v1.RouteRecordFsck, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	err = handleError(r)
	if err != nil {
		return err
	}

	body := util.ConvertBodyToByteArray(r.Body, *printJson)
	var rfr v1.RecordFsckReply
	err = json.Unmarshal(body, &rfr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal RecordFsckReply: %v", err)
	}

	return nil
}

func _main() error {
	flag.Parse()
	if len(flag.Args()) == 0 {
		usage()
		return fmt.Errorf("must provide action")
	}

	port := "65535"
	if *testnet {
		port = "65534"
	}

	*rpchost = util.NormalizeAddress(*rpchost, port)

	// Set port if not specified.
	u, err := url.Parse("https://" + *rpchost)
	if err != nil {
		return err
	}
	*rpchost = u.String()

	// Generate ed25519 identity to save messages, tokens etc.
	idf := util.CleanAndExpandPath(*identityFilename)
	if !util.FileExists(idf) {
		err = os.MkdirAll(defaultHomeDir, 0700)
		if err != nil {
			return err
		}
		fmt.Println("Generating signing identity...")
		id, err := identity.New()
		if err != nil {
			return err
		}
		err = id.Save(idf)
		if err != nil {
			return err
		}
		fmt.Println("Signing identity created...")
	}

	// Load identity.
	myID, err = identity.LoadFullIdentity(idf)
	if err != nil {
		return err
	}

	// See if we have a remote identity stored
	pkf := util.CleanAndExpandPath(*publicKeyFilename)
	if !util.FileExists(pkf) {
		if len(flag.Args()) != 1 || flag.Args()[0] != "publickey" {
			return fmt.Errorf("Missing remote signing key. Use " +
				"the 'publickey' command to retrieve it")
		}
	} else {
		// Load public key
		pk, err := ioutil.ReadFile(pkf)
		if err != nil {
			return err
		}
		publicKey, err = der.UnmarshalPublicKey(pk)
		if err != nil {
			return err
		}
	}

	// Scan through command line arguments.
	for i, a := range flag.Args() {
		// Select action
		if i == 0 {
			switch a {
			case "list":
				return list()
			case "publickey":
				return getPublicKey()
			case "recordappend":
				return recordAppend()
			case "recordnew":
				return recordNew()
			case "recordget":
				return recordGet()
			case "recordentriesget":
				return recordEntriesGet()
			case "fsck":
				return recordFsck()
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
