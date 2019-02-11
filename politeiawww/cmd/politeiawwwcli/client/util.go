// Copyright (c) 2018-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/json"
	"fmt"
	"os"
)

func PrettyPrintJSON(v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("MarshalIndent: %v", err)
	}
	fmt.Fprintf(os.Stdout, "%s\n", b)
	return nil
}
