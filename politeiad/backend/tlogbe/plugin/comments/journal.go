// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import "encoding/json"

const (
	// JournalVersion is the current version of the comments journal.
	journalVersion = "1"

	// keyPrefixJournal is the prefix to the key-value store key for a
	// journal record.
	keyPrefixJournal = "journal"

	// Journal actions
	journalActionAdd    = "add"    // Add entry
	journalActionEdit   = "edit"   // Edit entry
	journalActionDel    = "del"    // Delete entry
	journalActionCensor = "censor" // Censor entry
	journalActionVote   = "vote"   // Vote on entry
)

var (
	// Pregenerated journal actions
	journalAdd    []byte
	journalEdit   []byte
	journalDel    []byte
	journalCensor []byte
	journalVote   []byte
)

// journalAction prefixes and determines what the next structure is in the JSON
// journal.
type journalAction struct {
	Version string `json:"version"`
	Action  string `json:"action"`
}

type actionAdd struct {
	ParentID  uint32 `json:"parentid"`
	Comment   string `json:"comment"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
	CommentID uint32 `json:"commentid"`
	Receipt   string `json:"receipt"`
	Timestamp int64  `json:"timestamp"`
}

type actionEdit struct{}

type actionDel struct{}

type actionCensor struct{}

type actionVote struct{}

// keyJournal returns the key-value store key for a journal record. The token
// is not included in any journal actions since it is a static value and is
// already part of the key.
func keyJournal(token string) string {
	return keyPrefixJournal + token
}

// init is used to pregenerate the JSON journal actions.
func init() {
	var err error
	journalAdd, err = json.Marshal(journalAction{
		Version: journalVersion,
		Action:  journalActionAdd,
	})
	if err != nil {
		panic(err.Error())
	}
	journalEdit, err = json.Marshal(journalAction{
		Version: journalVersion,
		Action:  journalActionEdit,
	})
	if err != nil {
		panic(err.Error())
	}
	journalDel, err = json.Marshal(journalAction{
		Version: journalVersion,
		Action:  journalActionDel,
	})
	if err != nil {
		panic(err.Error())
	}
	journalCensor, err = json.Marshal(journalAction{
		Version: journalVersion,
		Action:  journalActionCensor,
	})
	if err != nil {
		panic(err.Error())
	}
	journalVote, err = json.Marshal(journalAction{
		Version: journalVersion,
		Action:  journalActionVote,
	})
	if err != nil {
		panic(err.Error())
	}
}
