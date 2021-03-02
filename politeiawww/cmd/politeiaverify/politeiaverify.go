package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/util"
)

// record is used to unmarshal the data that is contained in the record JSON
// bundle downloded from the GUI.
type record struct {
	Record          rcv1.Record `json:"record"`
	ServerPublicKey string      `json:"serverpublickey"`
}

// comments is used to unmarshal the data that is contained in the comments
// JSON bundle downloded from the GUI.
type comments []struct {
	CommentID       string `json:"commentid"`
	Receipt         string `json:"receipt"`
	Signature       string `json:"signature"`
	ServerPublicKey string `json:"serverpublickey"`
}

var (
	flagVerifyRecord   = flag.Bool("record", false, "Verify record bundle")
	flagVerifyComments = flag.Bool("comments", false, "Verify comments bundle")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeiaverify [flags] <bundle>\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, " <bundle> - Path to the JSON bundle "+
		"downloaded from the GUI\n")
	fmt.Fprintf(os.Stderr, "\n")
}

func verifyRecord(payload []byte) error {
	var r record
	err := json.Unmarshal(payload, &r)
	if err != nil {
		return fmt.Errorf("Record bundle JSON in bad format, make sure to " +
			"download it from the GUI.")
	}

	err = client.RecordVerify(r.Record, r.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("Failed to verify record: %v", err)
	}

	fmt.Println("Censorship record:")
	fmt.Printf("  Token      : %s\n", r.Record.CensorshipRecord.Token)
	fmt.Printf("  Merkle root: %s\n", r.Record.CensorshipRecord.Merkle)
	fmt.Printf("  Public key : %s\n", r.ServerPublicKey)
	fmt.Printf("  Signature  : %s\n\n", r.Record.CensorshipRecord.Signature)
	fmt.Println("Record successfully verified")

	return nil
}

func verifyComments(payload []byte) error {
	var comments comments
	err := json.Unmarshal(payload, &comments)
	if err != nil {
		return fmt.Errorf("Comments bundle JSON in bad format, make sure to " +
			"download it from the GUI.")
	}

	for _, c := range comments {
		// Verify receipt
		id, err := util.IdentityFromString(c.ServerPublicKey)
		if err != nil {
			return err
		}
		receipt, err := util.ConvertSignature(c.Receipt)
		if err != nil {
			return err
		}
		if !id.VerifyMessage([]byte(c.Signature), receipt) {
			return fmt.Errorf("Could not verify receipt %v of comment id %v",
				c.Receipt, c.CommentID)
		}
		fmt.Printf("Comment ID: %s\n", c.CommentID)
		fmt.Printf("  Public key: %s\n", c.ServerPublicKey)
		fmt.Printf("  Receipt   : %s\n", c.Receipt)
		fmt.Printf("  Signature : %s\n", c.Signature)
	}

	fmt.Println("\nComments successfully verified")

	return nil
}

func _main() error {
	flag.Parse()
	args := flag.Args()

	// Validate flags and arguments
	switch {
	case len(args) != 1:
		usage()
		return fmt.Errorf("Must provide json bundle path as input")
	case *flagVerifyRecord && *flagVerifyComments:
		usage()
		return fmt.Errorf("Must choose only one verification type")
	}

	// Read bundle payload
	file := args[0]
	var payload []byte
	payload, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	// Call verify method
	switch {
	case *flagVerifyRecord:
		return verifyRecord(payload)
	case *flagVerifyComments:
		return verifyComments(payload)
	default:
		// No flags used, read filename and try to call corresponding
		// verify method
		if strings.Contains(path.Base(file), "comments") {
			return verifyComments(payload)
		}
		return verifyRecord(payload)
	}
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
