// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"fmt"
	"net/http"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/gorilla/schema"
)

// ParseGetParams parses the query params from the GET request into
// a struct. This method requires the struct type to be defined
// with `schema` tags.
func ParseGetParams(r *http.Request, dst interface{}) error {
	err := r.ParseForm()
	if err != nil {
		return err
	}

	return schema.NewDecoder().Decode(dst, r.Form)
}

// RemoteAddr returns a string of the remote address, i.e. the address that
// sent the request.
func RemoteAddr(r *http.Request) string {
	via := r.RemoteAddr
	xff := r.Header.Get(pdv1.Forward)
	if xff != "" {
		return fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	return via
}
