// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package main

import (
	"testing"

	v2 "github.com/decred/politeia/politeiad/api/v2"
	"github.com/pkg/errors"
)

func TestExecConcurrently(t *testing.T) {
	// NOTE: these tests should be executed using the -race flag since
	// they are testing the concurrent execution of plugin commands.

	// Setup random tokens
	var (
		token        = "114cb8a95cb86355"
		invalidToken = "zzz"
	)

	// Setup a basic test case of plugin commands. The
	// command payload is used to mark the ordering of
	// the plugin commands so that the test can verify
	// that the batch does not change the ordering.
	pluginCmds := []v2.PluginCmd{
		// Success with a token
		{
			Token:   token,
			ID:      testPluginID,
			Command: testCmdSuccess,
			Payload: "0",
		},
		// Success without a token
		{
			Token:   token,
			ID:      testPluginID,
			Command: testCmdSuccess,
			Payload: "1",
		},
		// Invalid token
		{
			Token:   invalidToken,
			ID:      testPluginID,
			Command: testCmdSuccess,
			Payload: "2",
		},
		// Error case
		{
			Token:   token,
			ID:      testPluginID,
			Command: testCmdError,
			Payload: "3",
		},
	}

	// Setup the batch and execute the commands
	b := newBatch(pluginCmds)
	b.execConcurrently(testPluginRead)

	// Verify the replies
	for i, entry := range b.entries {
		// Verify that the batch entries are in the same order
		// that the plugin commands were provided in. The
		// command payloads were set to unique strings in order
		// to verify this.
		pluginCmd := pluginCmds[i]
		if entry.cmd.Payload != pluginCmd.Payload {
			t.Errorf("batch commands ordered incorrectly: got %v, want %v",
				entry.cmd.Payload, pluginCmd.Payload)
		}

		// Verify that either a reply payload was returned or
		// the error field has been populated.
		switch {
		case entry.reply != "" && entry.err != nil:
			// Both fields were populated
			t.Errorf("both the reply payload and the error were populated")

		case entry.reply == "" && entry.err == nil:
			// Neither field were populated
			t.Errorf("neither the reply payload or the error were populated")
		}

		// Verify that the reply is correct
		switch {
		case entry.cmd.Token == invalidToken:
			// An invalid token was provided. The error
			// should be an invalid token user error.
			var ue v2.UserErrorReply
			if !errors.As(entry.err, &ue) ||
				ue.ErrorCode != v2.ErrorCodeTokenInvalid {
				t.Errorf("wrong error; got %v, want %v user error",
					entry.err, v2.ErrorCodes[v2.ErrorCodeTokenInvalid])
			}

		case entry.cmd.Command == testCmdSuccess:
			// Success case
			if entry.reply != successReply {
				t.Errorf("wrong reply payload; got %v, want %v",
					entry.reply, successReply)
			}

		case entry.cmd.Command == testCmdError:
			// Error case
			if !errors.Is(entry.err, errorReply) {
				t.Errorf("wrong error reply; got %v, want %v",
					entry.err, errorReply)
			}

		default:
			t.Fatalf("unhandled test case: %v %v", entry, pluginCmd)
		}
	}

	// Test concurrency race conditions by executing a large
	// number of plugin command. If a race condition occurs,
	// the golang race detector should pick it up.
	cmdCount := 1000
	pluginCmds = make([]v2.PluginCmd, 0, cmdCount)
	for i := 0; i < cmdCount; i++ {
		pluginCmds = append(pluginCmds, v2.PluginCmd{
			Token:   "",
			ID:      testPluginID,
			Command: testCmdSuccess,
			Payload: "",
		})
	}

	// Setup the batch and execute the commands. If a race
	// condition does not occur then this test passes.
	b = newBatch(pluginCmds)
	b.execConcurrently(testPluginRead)
}

const (
	// testPluginID is the plugin ID for the test plugin.
	testPluginID = "test-plugin"

	// Plugin test commands
	testCmdSuccess = "test-cmd-success"
	testCmdError   = "test-cmd-error"
)

var (
	// Expected replies
	successReply = "success-reply-payload"
	errorReply   = errors.New("test command error reply")
)

// testPluginRead is the plugin read function that is used for testing.
func testPluginRead(token []byte, pluginID, cmd, payload string) (string, error) {
	switch cmd {
	case testCmdSuccess:
		return successReply, nil
	case testCmdError:
		return "", errorReply
	}
	return "", errors.Errorf("invalid command '%v'", cmd)
}
