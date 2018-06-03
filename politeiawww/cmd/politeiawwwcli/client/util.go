package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/agl/ed25519"
	"github.com/decred/politeia/politeiad/api/v1/identity"
)

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
