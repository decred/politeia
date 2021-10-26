// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"database/sql"
	"time"

	"github.com/pkg/errors"
)

const (
	// timeoutOp is the timeout for a single database operation.
	timeoutOp = 1 * time.Minute

	// timeoutTx is the timeout for a database transaction.
	timeoutTx = 3 * time.Minute
)

// beginTx returns a database transactions and a cancel function for the
// transaction if the user layer is enabled.
//
// The cancel function can be used up until the tx is committed or manually
// rolled back. Invoking the cancel function rolls the tx back and releases all
// resources associated with it. This allows the caller to defer the cancel
// function in order to rollback the tx on unexpected errors. Once the tx is
// successfully committed the deferred invocation of the cancel function does
// nothing.
func (p *politeiawww) beginTx() (*sql.Tx, func(), error) {
	ctx, cancel := ctxForTx()

	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := p.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	return tx, cancel, nil
}

// ctxForOp returns a context and cancel function for a single database
// operation.
func ctxForOp() (context.Context, func()) {
	return context.WithTimeout(context.Background(), timeoutOp)
}

// ctxForTx returns a context and a cancel function for a database transaction.
func ctxForTx() (context.Context, func()) {
	return context.WithTimeout(context.Background(), timeoutTx)
}
