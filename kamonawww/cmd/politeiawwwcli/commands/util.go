package commands

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/agl/ed25519"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh/terminal"
)

func Print(body interface{}, verbose, rawJSON bool) error {
	switch {
	case verbose:
		// Verbose printing is handled in the client
	case rawJSON:
		// Print raw JSON with no formatting
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("Marshal: %v", err)
		}
		fmt.Printf("%v\n", string(b))
	default:
		// Pretty print the body
		b, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			return fmt.Errorf("MarshalIndent: %v\n", err)
		}
		fmt.Fprintf(os.Stdout, "%s\n", b)
	}

	return nil
}

// PromptPassphrase is used to prompt the user for the private passphrase to
// their wallet.
func PromptPassphrase() ([]byte, error) {
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

// Digest returns the hex encoded SHA3-256 of a string.
func DigestSHA3(s string) string {
	h := sha3.New256()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// NewIdentity generates a new FullIdentity using randomly generated data to
// create the public/private key pair.
func NewIdentity() (*identity.FullIdentity, error) {
	b, err := util.Random(32)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(b[:])
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}

	id := &identity.FullIdentity{}
	copy(id.Public.Key[:], pub[:])
	copy(id.PrivateKey[:], priv[:])
	return id, nil
}

// merkleRoot converts the passed in list of files into SHA256 digests, then
// calculates and returns the merkle root of the digests.
func merkleRoot(files []v1.File) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no proposal files found")
	}

	digests := make([]*[sha256.Size]byte, len(files))
	for i, f := range files {
		// TODO: compute file digest and check against f.Digest
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			return "", fmt.Errorf("could not convert digest")
		}
		digests[i] = &d
	}

	return hex.EncodeToString(merkle.Root(digests)[:]), nil
}

// SignMerkleRoot calculates the merkle root of the passed in list of files,
// signs the merkle root with the passed in identity and returns the signature.
func SignMerkleRoot(files []v1.File, id *identity.FullIdentity) (string, error) {
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

// VerifyProposal verifies the integrity of a proposal by verifying the
// proposal's merkle root (if the files are present), the proposal signature,
// and the censorship record signature.
func VerifyProposal(p v1.ProposalRecord, serverPubKey string) error {
	// Verify merkle root if proposal files are present
	if len(p.Files) > 0 {
		mr, err := merkleRoot(p.Files)
		if err != nil {
			return err
		}
		if mr != p.CensorshipRecord.Merkle {
			return fmt.Errorf("merkle roots do not match")
		}
	}

	// Verify proposal signature
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

	// Verify censorship record signature
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

// ConvertTicketHashes converts a slice of hexadecimal ticket hashes into
// a slice of byte slices.
func ConvertTicketHashes(h []string) ([][]byte, error) {
	hashes := make([][]byte, 0, len(h))
	for _, v := range h {
		h, err := chainhash.NewHashFromStr(v)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h[:])
	}
	return hashes, nil
}
