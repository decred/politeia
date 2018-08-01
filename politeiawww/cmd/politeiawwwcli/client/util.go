package client

import (
	"bytes"
	"crypto/sha256"
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

// merkleRoot converts the passed in list of files into SHA256 digests, then
// calculates and returns the merkle root of the digests.
func merkleRoot(files []v1.File) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no proposal files found")
	}

	digests := make([]*[sha256.Size]byte, len(files))
	for i, f := range files {
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			return "", fmt.Errorf("could not convert digest")
		}
		digests[i] = &d
	}

	return hex.EncodeToString(merkle.Root(digests)[:]), nil
}

// proposalSignature calculates the merkle root of the passed in list of files,
// signs the merkle root with the passed in identity and returns the signature.
func proposalSignature(files []v1.File, id *identity.FullIdentity) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no proposal files found")
	}
	mr, err := merkleRoot(files)
	if err != nil {
		return "", err
	}
	sig := id.SignMessage([]byte(mr))
	return hex.EncodeToString(sig[:]), nil
}

// verifyProposal verifies the integrity of a proposal by verifying the
// proposal's merkle root (if the files are present), the proposal signature,
// and the censorship record signature.
func verifyProposal(p v1.ProposalRecord, serverPubKey string) error {
	// Verify merkle root if proposal files are present.
	if len(p.Files) > 0 {
		mr, err := merkleRoot(p.Files)
		if err != nil {
			return err
		}
		if mr != p.CensorshipRecord.Merkle {
			return fmt.Errorf("merkle roots do not match")
		}
	}

	// Verify proposal signature.
	pid, err := util.IdentityFromString(p.PublicKey)
	if err != nil {
		return err
	}
	sig, err := util.ConvertSignature(p.Signature)
	if err != nil {
		return err
	}
	if !pid.VerifyMessage([]byte(p.CensorshipRecord.Merkle), sig) {
		return fmt.Errorf("could not verify proposal signature")
	}

	// Verify censorship record signature.
	id, err := util.IdentityFromString(serverPubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(p.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	msg := []byte(p.CensorshipRecord.Merkle + p.CensorshipRecord.Token)
	if !id.VerifyMessage(msg, s) {
		return fmt.Errorf("could not verify censorship record signature")
	}

	return nil
}
