package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	v1 "github.com/thi4go/politeia/tlog/api/v1"
)

func TestBlob(t *testing.T) {
	re := v1.RecordEntry{
		PublicKey: "ma key yo",
		Hash:      "ma hash yo",
		Signature: "ma signature yo",
		DataHint:  "ma data hint yo",
		Data:      strings.Repeat("ma data yo", 1000),
	}
	blob, err := blobify(re)
	if err != nil {
		t.Fatal(err)
	}
	red, err := deblob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(re, *red) {
		t.Fatalf("want %v, got %v", spew.Sdump(re), spew.Sdump(red))
	}
}

func TestFilesystemEncrypt(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}

	dir, err := ioutil.TempDir("", "fsencrypted")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	fs, err := BlobFilesystemNew(key, dir)
	if err != nil {
		t.Fatal(err)
	}

	// use a key as random data
	b, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 32)
	copy(blob, b[:])
	id, err := fs.Put(blob)
	if err != nil {
		t.Fatal(err)
	}

	data, err := fs.Get(id)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, blob) {
		t.Fatal("data corruption")
	}
}

func TestFilesystem(t *testing.T) {
	dir, err := ioutil.TempDir("", "fs")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	fs, err := BlobFilesystemNew(nil, dir)
	if err != nil {
		t.Fatal(err)
	}

	// use a key as random data
	b, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 32)
	copy(blob, b[:])
	id, err := fs.Put(blob)
	if err != nil {
		t.Fatal(err)
	}

	data, err := fs.Get(id)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, blob) {
		t.Fatal("data corruption")
	}

	// Test Del
	err = fs.Del(id)
	if err != nil {
		t.Fatal(err)
	}

	// Test enum
	files := 10
	objects := make(map[string]struct{}, files)
	for i := 0; i < files; i++ {
		id, err := fs.Put(blob)
		if err != nil {
			t.Fatal(err)
		}
		objects[string(id)] = struct{}{}
	}
	x := 0
	f := func(myId []byte, myBlob []byte) error {
		x++
		t.Logf("%s", string(myId))
		if !bytes.Equal(data, myBlob) {
			t.Fatalf("data corruption %v %v", x, string(myId))
		}
		delete(objects, string(myId))
		return nil
	}
	err = fs.Enum(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 0 {
		t.Fatalf("invalid map count got %v, want %v", len(objects), 0)
	}
	if x != files {
		t.Fatalf("invalid blob count got %v, want %v", x, files)
	}
}
