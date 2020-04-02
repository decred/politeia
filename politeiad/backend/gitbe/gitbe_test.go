// Copyright (c) 2017-2018 The Decred developers
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
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	"github.com/thi4go/politeia/politeiad/api/v1/mime"
	"github.com/thi4go/politeia/politeiad/backend"
	"github.com/thi4go/politeia/util"
	"github.com/decred/slog"
)

func validateMD(got, want *backend.RecordMetadata) error {
	if got.Iteration != want.Iteration+1 ||
		got.Status != backend.MDStatusVetted ||
		want.Status != backend.MDStatusUnvetted ||
		got.Merkle != want.Merkle ||
		got.Token != want.Token {
		return fmt.Errorf("unexpected rm got %v, wanted %v",
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
	log := slog.NewBackend(&testWriter{t}).Logger("TEST")
	UseLogger(log)

	dir, err := ioutil.TempDir("", "politeia.test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Initialize stuff we need
	g, err := New(&chaincfg.TestNet3Params, dir, "", "", nil,
		testing.Verbose(), "")
	if err != nil {
		t.Fatal(err)
	}
	g.test = true

	// Create 5 unvetted records
	propCount := 5
	fileCount := 3
	t.Logf("===== CREATE %v RECORDS WITH %v FILES =====", propCount,
		fileCount)
	rm := make([]*backend.RecordMetadata, propCount)
	allFiles := make([][]backend.File, propCount)
	for i := 0; i < propCount; i++ {
		name := fmt.Sprintf("record%v", i)
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
				MIME:    mime.DetectMimeType([]byte(payload)),
				Digest:  digest,
				Payload: b64,
			})
		}
		allFiles[i] = files

		rm[i], err = g.New([]backend.MetadataStream{{
			ID:      0, // XXX
			Payload: "this is metadata",
		}}, files)
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
		for _, v := range rm {
			s := strings.Trim(branch, " \n")
			if s == v.Token {
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

	// Read all MDs from the branches and call getunvetted to verify
	// integrity
	for k, v := range rm {
		token, err := hex.DecodeString(v.Token)
		if err != nil {
			t.Fatal(err)
		}
		pru, err := g.GetUnvetted(token)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if !reflect.DeepEqual(&pru.RecordMetadata, rm[k]) {
			t.Fatalf("unexpected rm got %v, wanted %v",
				spew.Sdump(pru.RecordMetadata),
				spew.Sdump(rm[k]))
		}
		if !reflect.DeepEqual(pru.Files, allFiles[k]) {
			t.Fatalf("unexpected payload got %v, wanted %v",
				spew.Sdump(pru.Files), spew.Sdump(allFiles[k]))
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

	// Vet 1 of the records
	t.Logf("===== VET RECORD 1 =====")
	emptyMD := []backend.MetadataStream{}
	token, err := hex.DecodeString(rm[1].Token)
	if err != nil {
		t.Fatal(err)
	}
	record, err := g.SetUnvettedStatus(token,
		backend.MDStatusVetted, emptyMD, emptyMD)
	if err != nil {
		t.Fatal(err)
	}
	if record.RecordMetadata.Status != backend.MDStatusVetted {
		t.Fatalf("unexpected status: got %v wanted %v",
			record.RecordMetadata.Status, backend.MDStatusVetted)
	}
	//Get it as well to validate the GetVetted call
	pru, err := g.GetVetted(token, "")
	if err != nil {
		t.Fatal(err)
	}
	psrG := &pru.RecordMetadata
	if psrG.Status != backend.MDStatusVetted {
		t.Fatalf("unexpected status: got %v wanted %v", psrG.Status,
			backend.MDStatusVetted)
	}

	err = validateMD(psrG, rm[1])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pru.Files, allFiles[1]) {
		t.Fatalf("unexpected payload got %v, wanted %v",
			spew.Sdump(pru.Files), spew.Sdump(allFiles[1]))
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
	// Read anchor pointed at by merkle from git log
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
	// Read anchor again pointed at by merkle from git log
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
	token2, err := hex.DecodeString(rm[2].Token)
	if err != nil {
		t.Fatal(err)
	}
	_, err = g.SetUnvettedStatus(token2, backend.MDStatusVetted,
		emptyMD, emptyMD)
	if err != nil {
		t.Fatal(err)
	}
	err = g.anchorAllRepos()
	if err != nil {
		t.Fatal(err)
	}

	// Vet + anchor
	token0, err := hex.DecodeString(rm[0].Token)
	if err != nil {
		t.Fatal(err)
	}
	_, err = g.SetUnvettedStatus(token0, backend.MDStatusVetted,
		emptyMD, emptyMD)
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

func TestFilePathVersion(t *testing.T) {
	dir, err := ioutil.TempDir("", "pathversion")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	t.Logf("dir: %v", dir)
	d, err := _joinLatest(dir)
	if err != backend.ErrRecordNotFound {
		t.Fatal(err)
	}
	if d != "" {
		t.Fatalf("expected \"\", got %v", d)
	}

	// Create version 0 and check again
	newDir := pijoin(dir, "0")
	err = os.MkdirAll(newDir, 0766)
	if err != nil {
		t.Fatal(err)
	}
	testDir := joinLatest(dir)
	// Abuse filepath.Split by pretending 0 is a file
	splitDir, splitFile := filepath.Split(testDir)
	if splitDir != dir+"/" {
		t.Fatalf("invalid dir, expected %v, got %v", dir+"/", splitDir)
	}
	if splitFile != "0" {
		t.Fatalf("invalid dir, expected 0, got %v", splitFile)
	}

	// Create version 1 and check again
	newDir = pijoin(dir, "1")
	err = os.MkdirAll(newDir, 0766)
	if err != nil {
		t.Fatal(err)
	}
	testDir = joinLatest(dir)
	// Abuse filepath.Split by pretending 1 is a file
	splitDir, splitFile = filepath.Split(testDir)
	if splitDir != dir+"/" {
		t.Fatalf("invalid dir, expected %v, got %v", dir+"/", splitDir)
	}
	if splitFile != "1" {
		t.Fatalf("invalid dir, expected 1, got %v", splitFile)
	}

	// Create version 33 and check again
	newDir = pijoin(dir, "33")
	err = os.MkdirAll(newDir, 0766)
	if err != nil {
		t.Fatal(err)
	}
	testDir = joinLatest(dir)
	// Abuse filepath.Split by pretending 33 is a file
	splitDir, splitFile = filepath.Split(testDir)
	if splitDir != dir+"/" {
		t.Fatalf("invalid dir, expected %v, got %v", dir+"/", splitDir)
	}
	if splitFile != "33" {
		t.Fatalf("invalid dir, expected 33, got %v", splitFile)
	}
}

func TestUpdateReadme(t *testing.T) {
	dir, err := ioutil.TempDir("", "politeia.test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	g, err := New(&chaincfg.TestNet3Params, dir, "", "", nil,
		testing.Verbose(), "")
	if err != nil {
		t.Fatal(err)
	}
	g.test = true

	updatedReadmeContent := "Updated Readme Content!! \n"
	err = g.UpdateReadme(updatedReadmeContent)
	if err != nil {
		t.Fatal(err)
	}

	unvettedReadmePath := filepath.Join(g.unvetted, "README.md")
	unvettedReadmeContent, err := ioutil.ReadFile(unvettedReadmePath)
	if err != nil {
		t.Fatal(err)
	}
	unvettedReadmeString := string(unvettedReadmeContent)
	if unvettedReadmeString != updatedReadmeContent {
		t.Fatalf("Expected README.md content to be: %s \n but got: %s ",
			updatedReadmeContent,
			unvettedReadmeString)
	}

	vettedReadmePath := filepath.Join(g.vetted, "README.md")
	vettedReadmeContent, err := ioutil.ReadFile(vettedReadmePath)
	if err != nil {
		t.Fatal(err)
	}
	vettedReadmeString := string(vettedReadmeContent)
	if vettedReadmeString != updatedReadmeContent {
		t.Fatalf("Expected README.md content to be: %s \n but got: %s ",
			updatedReadmeContent,
			vettedReadmeString)
	}

	branches, err := g.git(g.unvetted, "branch")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("Expected 1 branch in unvetted repo, but it got %v",
			len(branches))
	}
	if !strings.HasSuffix(branches[0], "master") {
		t.Fatalf("The only branch in the vetted repo should be master")
	}

	branches, err = g.git(g.vetted, "branch")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("Expected 1 branch in vetted repo, but it got %v",
			len(branches))
	}
	if !strings.HasSuffix(branches[0], "master") {
		t.Fatalf("The only branch in the vetted repo should be master")
	}

	// Trying to update readme to the same content returns an error, but does
	// not add any new branches.
	err = g.UpdateReadme(updatedReadmeContent)
	if err == nil {
		t.Fatal("Updating readme the current content should return an error")
	}

	branches, err = g.git(g.unvetted, "branch")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("Expected 1 branch in unvetted repo, but it got %v",
			len(branches))
	}
	if !strings.HasSuffix(branches[0], "master") {
		t.Fatalf("The only branch in the vetted repo should be master")
	}

	branches, err = g.git(g.vetted, "branch")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("Expected 1 branch in vetted repo, but it got %v",
			len(branches))
	}
	if !strings.HasSuffix(branches[0], "master") {
		t.Fatalf("The only branch in the vetted repo should be master")
	}
}
