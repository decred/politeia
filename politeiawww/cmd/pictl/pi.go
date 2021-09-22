// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
)

func printProposalSummary(token string, s piv1.Summary) {
	printf("Token : %v\n", token)
	printf("Status: %v\n", s.Status)
}
