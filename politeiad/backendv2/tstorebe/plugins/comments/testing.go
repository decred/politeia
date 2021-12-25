// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/decred/politeia/politeiad/plugins/comments"
)

// newTestCommentsPlugin returns a commentsPlugin that has been setup for
// testing.
func newTestCommentsPlugin(t *testing.T) (*commentsPlugin, func()) {
	// Create plugin data directory
	dataDir, err := ioutil.TempDir("", comments.PluginID)
	if err != nil {
		t.Fatal(err)
	}

	// Setup plugin context
	c := commentsPlugin{
		dataDir:          dataDir,
		commentLengthMax: comments.SettingCommentLengthMax,
		voteChangesMax:   comments.SettingVoteChangesMax,
		allowExtraData:   comments.SettingAllowExtraData,
		allowEdits:       comments.SettingAllowEdits,
		editPeriodTime:   comments.SettingEditPeriodTime,
	}

	return &c, func() {
		err = os.RemoveAll(dataDir)
		if err != nil {
			t.Fatal(err)
		}
	}
}
