// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gitbe

import (
	"crypto/sha256"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
)

var (
	testAnchor = Anchor{
		Type: AnchorUnverified,
		Digests: [][]byte{
			{0xde, 0xad, 0xbe, 0xef},
			{0xba, 0xdc, 0x0f, 0xfe},
		},
		Messages: []string{
			"First",
			"Second",
		},
		Time: time.Now().Unix(),
	}
	testLastAnchor = LastAnchor{
		Last:   []byte{0xde, 0xad, 0xbe, 0xef},
		Time:   time.Now().Unix(),
		Merkle: []byte{0xba, 0xdc, 0x0f, 0xfe},
	}
)

func TestEncodeDecodeAnchor(t *testing.T) {
	blob, err := encodeAnchor(testAnchor)
	if err != nil {
		t.Fatal(err)
	}

	a2, err := DecodeAnchor(blob)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(testAnchor, *a2) {
		t.Fatalf("want %v got %v", spew.Sdump(testAnchor),
			spew.Sdump(*a2))
	}
}

func TestWriteReadAnchor(t *testing.T) {
	dir, err := ioutil.TempDir("", "politeia.test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	g := gitBackEnd{}
	err = g.openDB(filepath.Join(dir, DefaultDbPath))
	if err != nil {
		t.Fatal(err)
	}
	key := [sha256.Size]byte{0xaa, 0x55}
	err = g.writeAnchorRecord(key, testAnchor)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := g.readAnchorRecord(key)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(testAnchor, *a2) {
		t.Fatalf("want %v got %v", spew.Sdump(testAnchor),
			spew.Sdump(*a2))
	}
}

func TestEncodeDecodeLastAnchor(t *testing.T) {
	blob, err := encodeLastAnchor(testLastAnchor)
	if err != nil {
		t.Fatal(err)
	}

	la2, err := DecodeLastAnchor(blob)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(testLastAnchor, *la2) {
		t.Fatalf("want %v got %v", spew.Sdump(testLastAnchor),
			spew.Sdump(*la2))
	}
}

func TestWriteReadLastAnchor(t *testing.T) {
	dir, err := ioutil.TempDir("", "politeia.test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	g := gitBackEnd{}
	err = g.openDB(filepath.Join(dir, DefaultDbPath))
	if err != nil {
		t.Fatal(err)
	}
	err = g.writeLastAnchorRecord(testLastAnchor)
	if err != nil {
		t.Fatal(err)
	}
	la2, err := g.readLastAnchorRecord()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(testLastAnchor, *la2) {
		t.Fatalf("want %v got %v", spew.Sdump(testLastAnchor),
			spew.Sdump(*la2))
	}
}
