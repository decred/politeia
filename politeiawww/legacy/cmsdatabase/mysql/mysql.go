// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	database "github.com/decred/politeia/politeiawww/legacy/cmsdatabase"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/decred/politeia/util"

	// MySQL driver.
	_ "github.com/go-sql-driver/mysql"
)

const (
	// Database options
	connTimeout     = 1 * time.Minute
	connMaxLifetime = 1 * time.Minute
	maxOpenConns    = 0 // 0 is unlimited
	maxIdleConns    = 100

	// Database user (read/write access)
	userPoliteiawww = "politeiawww"

	databaseID = "cmsdatabase"

	// Database table names.
	tableNameExchangeRates = "exchange_rates"

	// Key-value store keys.
	keyVersion = "version"
)

// tableExchangeRates defines the exchange rates table.
const tableExchangeRates = `
  created_at INT(11) NOT NULL,
  month INT(11) NOT NULL,
  year INT(11) NOT NULL,
  rate INT(11) NOT NULL
`

var (
	_ user.Database = (*mysql)(nil)
)

// mysql implements the user.Database interface.
type mysql struct {
	sync.RWMutex

	shutdown       bool                            // Backend is shutdown
	cmsDB          *sql.DB                         // Database context
	encryptionKey  *[32]byte                       // Data at rest encryption key
	pluginSettings map[string][]user.PluginSetting // [pluginID][]PluginSettings
}

type mysqlIdentity struct {
	publicKey   string
	userID      string
	activated   int64
	deactivated int64
}

func ctxWithTimeout() (context.Context, func()) {
	return context.WithTimeout(context.Background(), connTimeout)
}

func (m *mysql) isShutdown() bool {
	m.RLock()
	defer m.RUnlock()

	return m.shutdown
}

// exchangeRateNew creates a new exchange rate entry into the database.
// It is keyed by the month and the year.
//
// This function must be called using a transaction.
func (m *mysql) exchangeRateNew(ctx context.Context, tx *sql.Tx, rate *database.ExchangeRate) error {
	_, err := tx.ExecContext(ctx,
		"INSERT INTO exchange_rates (month, year, rate, created_at) VALUES (?, ?, ?, ?)",
		rate.Month, rate.Year, rate.ExchangeRate, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("exchangeRateNew: %v", err)
	}

	return nil
}

// ExchangeRateNew creates a new exchange rate record in the database.
//
// ExchangeRateNew satisfies the Database interface.
func (m *mysql) ExchangeRateNew(dbExchangeRate *database.ExchangeRate) error {
	log.Tracef("ExchangeRateNew: %v %v", dbExchangeRate.Month, dbExchangeRate.Year)

	if m.isShutdown() {
		return user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Start transaction.
	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := m.cmsDB.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("begin tx: %v", err)
	}
	defer tx.Rollback()

	err = m.exchangeRateNew(ctx, tx, dbExchangeRate)
	if err != nil {
		return err
	}

	// Commit transaction.
	if err := tx.Commit(); err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Errorf("rollback tx failed: commit:'%v' rollback:'%v'",
				err, err2))
		}
		return fmt.Errorf("commit tx: %v", err)
	}

	return nil
}

// Close shuts down the database.  All interface functions must return with
// errShutdown if the backend is shutting down.
//
// Close satisfies the Database interface.
func (m *mysql) Close() error {
	log.Tracef("Close")

	m.Lock()
	defer m.Unlock()

	// Zero out encryption key.
	util.Zero(m.encryptionKey[:])
	m.encryptionKey = nil

	m.shutdown = true
	return m.cmsDB.Close()
}

// New connects to a mysql instance using the given connection params,
// and returns a pointer to the created mysql struct.
func New(host, password, network, encryptionKey string) (*mysql, error) {
	// Connect to database.
	dbname := databaseID + "_" + network
	log.Infof("MySQL host: %v:[password]@tcp(%v)/%v", userPoliteiawww, host,
		dbname)

	h := fmt.Sprintf("%v:%v@tcp(%v)/%v", userPoliteiawww, password,
		host, dbname)
	db, err := sql.Open("mysql", h)
	if err != nil {
		return nil, err
	}

	// Verify database connection.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = db.PingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("db ping: %v", err)
	}

	// Setup database options.
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	// Setup exchange_rates table.
	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameExchangeRates, tableExchangeRates)
	_, err = db.Exec(q)
	if err != nil {
		return nil, fmt.Errorf("create %v table: %v", tableNameExchangeRates, err)
	}

	// Load encryption key.
	key, err := util.LoadEncryptionKey(log, encryptionKey)
	if err != nil {
		return nil, err
	}

	return &mysql{
		cmsDB:          db,
		encryptionKey:  key,
		pluginSettings: make(map[string][]user.PluginSetting),
	}, nil
}
