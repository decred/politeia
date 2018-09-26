// Copyright (c) 2016-2017 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/pmezard/go-difflib/difflib"
)

var (
	alice *FullIdentity
	bob   *FullIdentity
)

func TestNew(t *testing.T) {
	var err error

	alice, err = New()
	if err != nil {
		t.Fatalf("New alice: %v", err)
	}

	bob, err = New()
	if err != nil {
		t.Fatalf("New bob: %v", err)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	am, err := alice.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	a, err := UnmarshalFullIdentity(am)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(a, alice) {
		t.Fatalf("marshal/unmarshal failed")
	}
}

func TestMarshalUnmarshalPublic(t *testing.T) {
	am, err := alice.Public.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	a, err := UnmarshalPublicIdentity(am)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(*a, alice.Public) {
		d := difflib.UnifiedDiff{
			A:        difflib.SplitLines(spew.Sdump(*a)),
			B:        difflib.SplitLines(spew.Sdump(alice.Public)),
			FromFile: "original",
			ToFile:   "current",
			Context:  3,
		}
		text, err := difflib.GetUnifiedDiffString(d)
		if err != nil {
			panic(err)
		}
		t.Fatalf("marshal/unmarshal failed %v", text)
	}
}

func TestString(t *testing.T) {
	s := fmt.Sprintf("%v", alice.Public)
	ss := hex.EncodeToString(alice.Public.Key[:])
	if s != ss {
		t.Fatalf("stringer not working")
	}
}

func TestSign(t *testing.T) {
	message := []byte("this is a message")
	signature := alice.SignMessage(message)
	if !alice.Public.VerifyMessage(message, signature) {
		t.Fatalf("corrupt signature")
	}
}
