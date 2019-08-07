// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/decred/dcrtime/merkle"
)

func tempFile(size int) string {
	tmpfile, err := ioutil.TempFile("", "randomcontent")
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}
	blob, err := Random(size)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}
	data := base64.StdEncoding.EncodeToString(blob)
	err = ioutil.WriteFile(tmpfile.Name(), []byte(data), 0644)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	return tmpfile.Name()
}

func TestTimestamp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestTimestamp in short mode.")
	}

	filename := tempFile(512)
	defer os.Remove(filename)

	// use util internal functions ito get some free testing
	_, digest, _, err := LoadFile(filename)
	if err != nil {
		t.Fatalf("%v", err)
	}
	d, ok := ConvertDigest(digest)
	if !ok {
		t.Fatalf("not a valid digest")
	}

	err = Timestamp("test", defaultTestnetHost(), []*[sha256.Size]byte{&d})
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestVerify in short mode.")
	}

	// Use pre anchored digest
	digest := "44425372a555e6ac6dad89d5a5b05cd33385c0c9114c5e90e7861da31ae2f289"

	vr, err := Verify("test", defaultTestnetHost(), []string{digest})
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Verify reply
	if len(vr.Digests) != 1 {
		t.Fatalf("expected 1 response, got %v", len(vr.Digests))
	}
	d := vr.Digests[0]
	if digest != d.Digest {
		t.Fatalf("invalid digest expected %v got %v", digest, d.Digest)
	}
	expectedTX := "2aeb59d362752e73757e4b88812da784fe2f4118d2e28121f286b9fa0ef50c1d"
	if expectedTX != d.ChainInformation.Transaction {
		t.Fatalf("invalid tx expected %v got %v", expectedTX,
			d.ChainInformation.Transaction)
	}
	expectedMerkle := "74bdabc1613ab132490e59fe0551bca62a29c90eca88edeba650d021ac5eaecb"
	if expectedMerkle != d.ChainInformation.MerkleRoot {
		t.Fatalf("invalid merkle expected %v got %v", expectedMerkle,
			d.ChainInformation.MerkleRoot)
	}

	// Verify merkle root despite it being done Verify call
	root, err := merkle.VerifyAuthPath(&d.ChainInformation.MerklePath)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if expectedMerkle != hex.EncodeToString(root[:]) {
		t.Fatalf("unexpected merkle %v", hex.EncodeToString(root[:]))
	}
}
