// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
// +build !windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func (p *piv) statsHandler() {
	// Launch signal handler
	signalsChan := make(chan os.Signal, 1)
	signalsDone := make(chan struct{}, 1)
	signal.Notify(signalsChan, []os.Signal{syscall.SIGUSR1}...)

	for {
		select {
		case <-p.ctx.Done():
			// Shut down signal handler
			signal.Stop(signalsChan)
			close(signalsDone)
			return
		case <-signalsChan:
			fmt.Printf("----- politeiavoter status -----\n")
			p.dumpTogo()
			p.dumpComplete()
			p.dumpQueue()
		}
	}
}
