// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
// +build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func (c *client) statsHandler(ctx context.Context) {
	// Launch signal handler
	signalsChan := make(chan os.Signal, 1)
	signalsDone := make(chan struct{}, 1)
	signal.Notify(signalsChan, []os.Signal{syscall.SIGUSR1}...)

	for {
		select {
		case <-ctx.Done():
			// Shut down signal handler
			signal.Stop(signalsChan)
			close(signalsDone)
			return
		case <-signalsChan:
			fmt.Printf("----- politeiavoter status -----\n")
			c.dumpTogo()
			c.dumpComplete()
			c.dumpQueue()
		}
	}
}
