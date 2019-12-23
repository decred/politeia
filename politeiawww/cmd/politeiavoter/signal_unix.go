// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
// +build !windows

package main

import (
	"os"
	"syscall"
)

func init() {
	signals = []os.Signal{syscall.SIGUSR1}
}
