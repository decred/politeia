// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gitbe

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btclog"
	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

func validatePSR(got, want *backend.ProposalStorageRecord) error {
	if got.Version != want.Version+1 ||
		got.Status != backend.PSRStatusVetted ||
		want.Status != backend.PSRStatusUnvetted ||
		got.Merkle != want.Merkle ||
		got.Name != want.Name ||
		!bytes.Equal(got.Token, want.Token) {
		return fmt.Errorf("unexpected psr got %v, wanted %v",
			spew.Sdump(*got), spew.Sdump(*want))
	}

	return nil
}

func TestExtendUnextend(t *testing.T) {
	sha1Digest := make([]byte, sha1.Size)
	for i := 0; i < sha1.Size; i++ {
		sha1Digest[i] = byte(i)
	}

	sha256ExtendDigest := extendSHA1(sha1Digest)
	sha256UnextendDigest := unextendSHA256(sha256ExtendDigest)

	if !bytes.Equal(sha1Digest, sha256UnextendDigest) {
		t.Fatalf("unextend")
	}
}

func TestAnchorWithCommits(t *testing.T) {
	log := btclog.NewBackend(&testWriter{t}).Logger("TEST")
	UseLogger(log)

	dir, err := ioutil.TempDir("", "politeia.test")
	if err != nil {
		t.Fatal(err)
	}
	//defer os.RemoveAll(dir)

	// Initialize stuff we need
	g, err := New(dir, "", "", testing.Verbose())
	g.test = true

	// Create 5 unvetted proposals
	propCount := 5
	fileCount := 3
	t.Logf("===== CREATE %v PROPS WITH %v FILES =====", propCount,
		fileCount)
	psr := make([]*backend.ProposalStorageRecord, propCount)
	allFiles := make([][]backend.File, propCount)
	for i := 0; i < propCount; i++ {
		name := fmt.Sprintf("Prop %v", i)
		files := make([]backend.File, 0, fileCount)
		for j := 0; j < fileCount; j++ {
			r, err := util.Random(64)
			if err != nil {
				t.Fatal(err)
			}
			// Create text file
			payload := hex.EncodeToString(r)
			digest := hex.EncodeToString(util.Digest([]byte(payload)))
			// We expect base64 encoded content
			b64 := base64.StdEncoding.EncodeToString([]byte(payload))

			files = append(files, backend.File{
				Name:    name + "_" + strconv.Itoa(j),
				MIME:    http.DetectContentType([]byte(payload)),
				Digest:  digest,
				Payload: b64,
			})
		}
		allFiles[i] = files

		psr[i], err = g.New(name, files)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Expect propCount + master branches in unvetted
	branches, err := g.git(g.unvetted, "branch")
	if err != nil {
		t.Fatalf("%v", err)
	}
	found := 0
	master := 0
	for _, branch := range branches {
		for _, v := range psr {
			s := strings.Trim(branch, " \n")
			if s == hex.EncodeToString(v.Token) {
				found++
				break
			}
			if strings.HasSuffix(s, "master") {
				master++
				break
			}
		}
	}
	if found != propCount || master != 1 {
		t.Fatalf("unexpected props got %v wanted %v master %v",
			found, propCount, master)
	}

	// Read all PSRs from the branches and call getunvetted to verify
	// integrity
	for k, v := range psr {
		filesG, psrUnvetted, err := g.GetUnvetted(v.Token)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if !reflect.DeepEqual(psrUnvetted, psr[k]) {
			t.Fatalf("unexpected psr got %v, wanted %v",
				spew.Sdump(psrUnvetted), spew.Sdump(psr[k]))
		}
		if !reflect.DeepEqual(filesG, allFiles[k]) {
			t.Fatalf("unexpected payload got %v, wanted %v",
				spew.Sdump(filesG), spew.Sdump(allFiles[k]))
		}
	}

	// Expect 1 branch in vetted
	branches, err = g.git(g.vetted, "branch")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("too many branches on master got %v want 1",
			len(branches))
	}

	// Vet 1 of the proposals
	t.Logf("===== VET PROP 1 =====")
	status, err := g.SetUnvettedStatus(psr[1].Token, backend.PSRStatusVetted)
	if err != nil {
		t.Fatal(err)
	}
	if status != backend.PSRStatusVetted {
		t.Fatalf("unexpected status: got %v wanted %v", status,
			backend.PSRStatusVetted)
	}
	//Get it as well to validate the GetVetted call
	filesG, psrG, err := g.GetUnvetted(psr[1].Token)
	if err != nil {
		t.Fatal(err)
	}
	if psrG.Status != backend.PSRStatusVetted {
		t.Fatalf("unexpected status: got %v wanted %v", psrG.Status,
			backend.PSRStatusVetted)
	}

	err = validatePSR(psrG, psr[1])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(filesG, allFiles[1]) {
		t.Fatalf("unexpected payload got %v, wanted %v",
			spew.Sdump(filesG), spew.Sdump(allFiles[1]))
	}

	// Anchor all repos
	t.Logf("===== ANCHOR =====")
	err = g.anchorAllRepos()
	if err != nil {
		t.Fatal(err)
	}
	// Read unconfirmed and verify content
	unconfirmed, err := g.readUnconfirmedAnchorRecord()
	if err != nil {
		t.Fatal(err)
	}
	if len(unconfirmed.Merkles) != 1 {
		t.Fatalf("invalid merkles len %v", len(unconfirmed.Merkles))
	}
	// Read anchor pointed at by merkle from db
	var mr [sha256.Size]byte
	copy(mr[:], unconfirmed.Merkles[0])
	anchor, err := g.readAnchorRecord(mr)
	if err != nil {
		t.Fatal(err)
	}
	// Verify last commit
	lastGitDigest, err := g.gitLastDigest(g.vetted)
	if err != nil {
		t.Fatal(err)
	}
	lastGitDigest = extendSHA1(lastGitDigest)
	la, err := g.readLastAnchorRecord()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lastGitDigest, la.Last) {
		t.Fatalf("invalid unconfirmed digest got %x wanted %x",
			lastGitDigest, la.Last)
	}
	if anchor.Type != AnchorUnverified {
		t.Fatalf("invalid anchor type %v expected %v", anchor.Type,
			AnchorVerified)
	}

	// Anchor again and make sure nothing changed
	t.Logf("===== REANCHOR NOTHING TO DO =====")
	err = g.anchorAllRepos()
	if err != nil {
		t.Fatal(err)
	}
	// Read unconfirmed again and verify content
	unconfirmed2, err := g.readUnconfirmedAnchorRecord()
	if err != nil {
		t.Fatal(err)
	}
	if len(unconfirmed2.Merkles) != 1 {
		t.Fatalf("invalid merkles len %v", len(unconfirmed2.Merkles))
	}
	if !reflect.DeepEqual(unconfirmed, unconfirmed2) {
		t.Fatalf("unconfirmed got %v wanted %v",
			spew.Sdump(unconfirmed2),
			spew.Sdump(unconfirmed))
	}
	// Read anchor again pointed at by merkle from db
	var mr2 [sha256.Size]byte
	copy(mr2[:], unconfirmed.Merkles[0])
	anchor2, err := g.readAnchorRecord(mr2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mr[:], mr2[:]) {
		t.Fatalf("mr got %x wanted %x", mr2, mr)
	}
	// Verify last commit again
	lastGitDigest2, err := g.gitLastDigest(g.vetted)
	if err != nil {
		t.Fatal(err)
	}
	lastGitDigest2 = extendSHA1(lastGitDigest2)
	la2, err := g.readLastAnchorRecord()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lastGitDigest2, la2.Last) {
		t.Fatalf("invalid unconfirmed digest got %x wanted %x",
			lastGitDigest2, la2.Last)
	}
	if !bytes.Equal(lastGitDigest2, lastGitDigest) {
		t.Fatalf("invalid lastGitDigest got %x wanted %x",
			lastGitDigest2, lastGitDigest)
	}
	if !reflect.DeepEqual(anchor2, anchor) {
		t.Fatalf("invalid anchor got %x wanted %x",
			spew.Sdump(anchor2), spew.Sdump(anchor))
	}

	// Complete anchor
	t.Logf("===== COMPLETE ANCHOR PROCESS =====")
	err = g.anchorChecker()
	if err != nil {
		t.Fatal(err)
	}
	// Verify that we updated unconfirmed
	unconfirmed, err = g.readUnconfirmedAnchorRecord()
	if err != nil {
		t.Fatal(err)
	}
	if len(unconfirmed.Merkles) != 0 {
		t.Fatalf("invalid merkles len %v", len(unconfirmed.Merkles))
	}
	// Verify that anchor record was updated
	anchor3, err := g.readAnchorRecord(mr)
	if err != nil {
		t.Fatal(err)
	}
	if anchor3.Type != AnchorVerified {
		t.Fatalf("invalid anchor type %v expected %v", anchor3.Type,
			AnchorVerified)
	}
	if anchor3.Transaction != expectedTestTX {
		t.Fatalf("invalid anchor transation %v expected %v",
			anchor3.Transaction, expectedTestTX)
	}
	// Verify that Merkle was cleared in last anchor record
	la, err = g.readLastAnchorRecord()
	if err != nil {
		t.Fatal(err)
	}

	// Drop an anchor to verify that we don't pick up the anchor commit
	t.Logf("===== DROP ANCHOR ON TOP OF ANCHOR =====")
	lastGitDigest, err = g.gitLastDigest(g.vetted)
	if err != nil {
		t.Fatal(err)
	}
	err = g.anchorAllRepos()
	if err != nil {
		t.Fatal(err)
	}
	lastGitDigestAfter, err := g.gitLastDigest(g.vetted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lastGitDigest, lastGitDigestAfter) {
		t.Fatalf("git digest got %x wanted %x",
			lastGitDigest, lastGitDigestAfter)
	}

	// Interleave incomplete anchors:
	//	vet -> anchor1 -> vet -> anchor2 -> confirm

	// Vet + anchor
	t.Logf("===== INTERLEAVE ANCHORS =====")
	status, err = g.SetUnvettedStatus(psr[2].Token, backend.PSRStatusVetted)
	if err != nil {
		t.Fatal(err)
	}
	err = g.anchorAllRepos()
	if err != nil {
		t.Fatal(err)
	}

	// Vet + anchor
	status, err = g.SetUnvettedStatus(psr[0].Token, backend.PSRStatusVetted)
	if err != nil {
		t.Fatal(err)
	}
	err = g.anchorAllRepos()
	if err != nil {
		t.Fatal(err)
	}

	// Complete anchor
	t.Logf("===== COMPLETE INTERLEAVED ANCHOR PROCESS =====")
	err = g.anchorChecker()
	if err != nil {
		t.Fatal(err)
	}

	// Drop an anchor to verify that we don't pick up the anchor commit
	t.Logf("===== DROP ANCHOR ON TOP OF ANCHOR 2 =====")
	err = g.anchorAllRepos()
	if err != nil {
		t.Fatal(err)
	}

}
