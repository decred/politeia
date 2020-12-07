package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	wwwutil "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
)

// proposal is used to unmarshal the data that is cointaned in the proposal
// JSON bundles downloded from the GUI.
type proposal struct {
	PublicKey        string              `json:"publickey"`
	Signature        string              `json:"signature"`
	CensorshipRecord pi.CensorshipRecord `json:"censorshiprecord"`
	Files            []pi.File           `json:"files"`
	Metadata         []pi.Metadata       `json:"metadata"`
	ServerPublicKey  string              `json:"serverpublickey"`
}

// comments is used to unmarshal the data that is cointaned in the comments
// JSON bundles downloded from the GUI.
type comments []struct {
	CommentID       string `json:"commentid"`
	Receipt         string `json:"receipt"`
	Signature       string `json:"signature"`
	ServerPublicKey string `json:"serverpublickey"`
}

var (
	flagVerifyProposal = flag.Bool("proposal", false, "Verify proposal bundle")
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

func verifyProposal(payload []byte) error {
	var prop proposal
	err := json.Unmarshal(payload, &prop)
	if err != nil {
		return fmt.Errorf("Proposal bundle JSON in bad format, make sure to " +
			"download it from the GUI.")
	}

	// Verify merkle root
	merkle, err := wwwutil.MerkleRoot(prop.Files, prop.Metadata)
	if err != nil {
		return err
	}
	if merkle != prop.CensorshipRecord.Merkle {
		return fmt.Errorf("Merkle roots do not match: %v and %v",
			prop.CensorshipRecord.Merkle, merkle)
	}

	// Verify proposal signature
	id, err := util.IdentityFromString(prop.PublicKey)
	if err != nil {
		return err
	}
	sig, err := util.ConvertSignature(prop.Signature)
	if err != nil {
		return err
	}
	if !id.VerifyMessage([]byte(merkle), sig) {
		return fmt.Errorf("Invalid proposal signature %v", prop.Signature)
	}

	// Verify censorship record signature
	id, err = util.IdentityFromString(prop.ServerPublicKey)
	if err != nil {
		return err
	}
	sig, err = util.ConvertSignature(prop.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	if !id.VerifyMessage([]byte(merkle+prop.CensorshipRecord.Token), sig) {
		return fmt.Errorf("Invalid censhorship record signature %v",
			prop.CensorshipRecord.Signature)
	}

	fmt.Println("Proposal signature:")
	fmt.Printf("  Public key: %s\n", prop.PublicKey)
	fmt.Printf("  Signature : %s\n", prop.Signature)
	fmt.Println("Proposal censorship record signature:")
	fmt.Printf("  Merkle root: %s\n", prop.CensorshipRecord.Merkle)
	fmt.Printf("  Public key : %s\n", prop.ServerPublicKey)
	fmt.Printf("  Signature  : %s\n\n", prop.CensorshipRecord.Signature)
	fmt.Println("Proposal successfully verified")

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
	case *flagVerifyProposal && *flagVerifyComments:
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
	case *flagVerifyProposal:
		return verifyProposal(payload)
	case *flagVerifyComments:
		return verifyComments(payload)
	default:
		// No flags used, read filename and try to call corresponding
		// verify method
		if strings.Contains(path.Base(file), "comments") {
			return verifyComments(payload)
		}
		return verifyProposal(payload)
	}
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
