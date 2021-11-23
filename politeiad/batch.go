// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package main

import (
	"sync"

	v2 "github.com/decred/politeia/politeiad/api/v2"
	"github.com/decred/politeia/util"
)

// pluginRead contains the same function signature as the backendv2 PluginRead
// function. This allows test coverage to be added to the batch implemenation
// without needing to deal with a backendv2 stub.
type pluginRead func(token []byte, pluginID,
	cmd, payload string) (string, error)

// batch contains a batch of plugin commands and implements the methods that
// allow for the concurrent execution of these plugin commands.
type batch struct {
	sync.Mutex
	cmds []batchCmd
}

// batchCmd contains a single plugin command and the reply/error that resulted
// from the execution of the plugin command.
type batchCmd struct {
	cmd   v2.PluginCmd
	reply string // JSON encoded reply payload
	err   error  // Only set if an error is encountered
}

// newBatch returns a new batch.
func newBatch(pluginCmds []v2.PluginCmd) *batch {
	batchCmds := make([]batchCmd, 0, len(pluginCmds))
	for _, cmd := range pluginCmds {
		batchCmds = append(batchCmds, batchCmd{
			cmd: cmd,
		})
	}
	return &batch{
		cmds: batchCmds,
	}
}

// execConcurrently executes the batch of plugin commands concurrently.
func (b *batch) execConcurrently(fn pluginRead) {
	// Execute commands concurrently
	var wg sync.WaitGroup
	for i := 0; i < len(b.cmds); i++ {
		wg.Add(1)
		go b.execReadCmd(fn, b.getCmd(i), i, &wg)
	}

	// Wait for all commands to finish executing
	wg.Wait()
}

// execReadCmd executes a single plugin read-only command.
func (b *batch) execReadCmd(fn pluginRead, cmd v2.PluginCmd, index int, wg *sync.WaitGroup) {
	// Decrement the wait group on exit
	defer wg.Done()

	// Decode the token. The token is optional
	// for plugin reads.
	var (
		token []byte
		err   error
	)
	if cmd.Token != "" {
		token, err = decodeTokenAnyLength(cmd.Token)
		if err != nil {
			// Invalid token
			err = v2.UserErrorReply{
				ErrorCode:    v2.ErrorCodeTokenInvalid,
				ErrorContext: util.TokenRegexp(),
			}
			b.setReply(index, "", err)
			return
		}
	}

	// Execute the read command
	reply, err := fn(token, cmd.ID, cmd.Command, cmd.Payload)
	if err != nil {
		b.setReply(index, "", err)
		return
	}

	b.setReply(index, reply, nil)
}

// getCmd returns the PluginCmd at the provided index.
func (b *batch) getCmd(index int) v2.PluginCmd {
	b.Lock()
	defer b.Unlock()

	return b.cmds[index].cmd
}

// setReply sets the reply for the plugin command at that provided index.
func (b *batch) setReply(index int, reply string, err error) {
	b.Lock()
	defer b.Unlock()

	c := b.cmds[index]
	c.reply = reply
	c.err = err
	b.cmds[index] = c
}
