package mysql

import (
	"bytes"
	"testing"

	"github.com/decred/politeia/util"
)

func TestEncryptDecrypt(t *testing.T) {
	password := "passwordsosikrit"
	blob := []byte("encryptmeyo")

	// setup fake context
	s := &mysql{}
	s.getNonce = s.getTestNonce
	s.argon2idKey(password, util.NewArgon2Params())

	// Encrypt and make sure cleartext isn't the same as the encypted blob.
	eb, err := s.encrypt(nil, nil, blob)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(eb, blob) {
		t.Fatal("equal")
	}

	// Decrypt and make sure cleartext is the same as the initial blob.
	db, _, err := s.decrypt(eb)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(db, blob) {
		t.Fatal("not equal")
	}

	// Try to decrypt invalid blob.
	_, _, err = s.decrypt(blob)
	if err == nil {
		t.Fatal("expected invalid sbox header")
	}
}
