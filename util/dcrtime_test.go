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

	err = Timestamp(defaultTestnetHost(), []*[sha256.Size]byte{&d})
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestVerify in short mode.")
	}

	// Use pre anchored digest
	digest := "4458a9d635eabdc3c7d75e8e747cdbb94b2b166245eb7a197982ff2e100d960b"
	//digest2 := "18ba0bde80cc33cdec19206646940896436399d1f15223398242e042113a7e39"

	vr, err := Verify(defaultTestnetHost(), []string{digest})
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
	expectedTX := "cdec2565ac832d6ed1bcea1822cc4ddf06d8f9457a96dcddeec2b3eccbe94980"
	if expectedTX != d.ChainInformation.Transaction {
		t.Fatalf("invalid tx expected %v got %v", expectedTX,
			d.ChainInformation.Transaction)
	}
	expectedMerkle := "83c0c40f949cc4c02a2c51ed32246acdc7d00eb8a6ae07c67031b11d0db9752a"
	if expectedMerkle != d.ChainInformation.MerkleRoot {
		t.Fatalf("invalid tx expected %v got %v", expectedMerkle,
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
