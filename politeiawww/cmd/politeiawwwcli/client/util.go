package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"

	"github.com/agl/ed25519"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"golang.org/x/crypto/ssh/terminal"
)

func convertTicketHashes(h []string) ([][]byte, error) {
	hashes := make([][]byte, 0, len(h))
	for _, v := range h {
		hh, err := chainhash.NewHashFromStr(v)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hh[:])
	}
	return hashes, nil
}

func idFromString(s string) (*identity.FullIdentity, error) {
	// super hack alert, we are going to use the email address as the
	// privkey.  We do this in order to sign things as an admin later.
	buf := [32]byte{}
	copy(buf[:], []byte(s))
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

func prettyPrintJSON(v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("Could not marshal JSON: %v\n", err)
	}
	fmt.Fprintf(os.Stdout, "%s\n", b)
	return nil
}

// providePrivPassphrase is used to prompt for the private passphrase of the
// user's wallet
func providePrivPassphrase() ([]byte, error) {
	prompt := "Enter the private passphrase of your wallet: "
	for {
		fmt.Printf("%v", prompt)
		pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Printf("\n")
		pass = bytes.TrimSpace(pass)
		if len(pass) == 0 {
			continue
		}
		return pass, nil
	}
}

// getSignature signs the msg with the given identity and returns
// the encoded signature
func getSignature(msg []byte, id *identity.FullIdentity) (string, error) {
	sig := id.SignMessage(msg)
	return hex.EncodeToString(sig[:]), nil
}

// getProposalSignature takes as input a list of files and
// generates the merkle root with the file digests, then delegates to
// getSignature().
func getProposalSignature(files []v1.File, id *identity.FullIdentity) (string, error) {
	// Calculate the merkle root with the file digests.
	hashes := make([]*[sha256.Size]byte, 0, len(files))
	for _, v := range files {
		payload, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return "", err
		}

		digest := util.Digest(payload)
		var d [sha256.Size]byte
		copy(d[:], digest)
		hashes = append(hashes, &d)
	}

	var encodedMerkleRoot string
	if len(hashes) > 0 {
		encodedMerkleRoot = hex.EncodeToString(merkle.Root(hashes)[:])
	} else {
		encodedMerkleRoot = ""
	}
	return getSignature([]byte(encodedMerkleRoot), id)
}
