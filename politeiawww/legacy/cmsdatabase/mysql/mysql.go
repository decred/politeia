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
	tableNameInvoices      = "invoices"
	tableNameLineItems     = "line_items"
	tableNamePayments      = "payments"
	tableNameInvoiceChange = "invoice_changes"
	tableNameVersions      = "versions"

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
	_ database.Database = (*mysql)(nil)
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

// ExchangeRate returns exchange rate by month/year
func (m *mysql) ExchangeRate(month, year int) (*database.ExchangeRate, error) {
	log.Tracef("ExchangeRate: %v %v", month, year)

	if m.isShutdown() {
		return nil, user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	var rate uint
	err := m.cmsDB.QueryRowContext(ctx,
		"SELECT rate FROM exchange_rates WHERE month = ? AND year = ?", month, year).Scan(&rate)
	switch {
	case err == sql.ErrNoRows:
		return nil, database.ErrExchangeRateNotFound
	case err != nil:
		return nil, err
	}

	return &database.ExchangeRate{
		Month:        uint(month),
		Year:         uint(year),
		ExchangeRate: rate,
	}, nil
}

// Create new invoice.
//
// CreateInvoice satisfies the database interface.
func (m *mysql) NewInvoice(dbInvoice *database.Invoice) error {

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

	// CALL newInvoice here

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

// Update existing invoice.
//
// UpdateInvoice satisfies the database interface.
func (m *mysql) UpdateInvoice(dbInvoice *database.Invoice) error {

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

	// CALL updateInvoice here

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

// RemoveLineItem deletes an existing invoice line items from the database.
func (m *mysql) RemoveInvoiceLineItems(invoiceToken string) error {

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

	// CALL removeInvoiceLineItems here

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

// Return all invoices by userid
func (m *mysql) InvoicesByUserID(userid string) ([]database.Invoice, error) {
	return nil, nil
}

// InvoiceByToken Return invoice by its token.
func (m *mysql) InvoiceByToken(token string) (*database.Invoice, error) {
	return nil, nil
}

// InvoiceByKey Return invoice by its key.
func (m *mysql) InvoiceByKey(key string) (*database.Invoice, error) {
	return nil, nil
}

// InvoiceByTokenVersion Return invoice by its token and version
func (m *mysql) InvoiceByTokenVersion(token string, version string) (*database.Invoice, error) {
	return nil, nil
}

// InvoicesByMonthYearStatus returns all invoices by month year and status
func (m *mysql) InvoicesByMonthYearStatus(month, year uint16, status int) ([]database.Invoice, error) {
	return nil, nil
}

// InvoicesByMonthYear returns all invoices by month/year
func (m *mysql) InvoicesByMonthYear(month, year uint16) ([]database.Invoice, error) {
	return nil, nil
}

// InvoicesByStatus returns all invoices by status
func (m *mysql) InvoicesByStatus(status int) ([]database.Invoice, error) {
	return nil, nil
}

// InvoicesAll returns all invoices
func (m *mysql) InvoicesAll() ([]database.Invoice, error) {
	return nil, nil
}

// InvoicesByAddress return invoices by its payment address.
func (m *mysql) InvoicesByAddress(address string) ([]database.Invoice, error) {
	return nil, nil
}

// InvoicesByDateRangeStatus takes a start and end time (in Unix seconds) and returns
// all invoices with the included status.  This uses the
// invoice_changes table to discover the token to look up the correct line items.
func (m *mysql) InvoicesByDateRangeStatus(start, end int64, status int) ([]database.Invoice, error) {
	return nil, nil
}

// InvoicesByDateRange takes a start and end time (in Unix seconds) and returns
// all invoices.  This uses the
// invoice_changes table to discover the token to look up the correct line items.
func (m *mysql) InvoicesByDateRange(start, end int64) ([]database.Invoice, error) {
	return nil, nil
}

// InvoicesByLineItemsProposalToken takes a proposal token as an argument and
// returns all invoices that have line items corresponding with that token.
// All line items that are not considered relevant to the proposal token will
// be omitted.
func (m *mysql) InvoicesByLineItemsProposalToken(token string) ([]database.Invoice, error) {
	return nil, nil
}

// MatchingLineItems is a type used for finding matched line items based on
// proposal ownership.
type MatchingLineItems struct {
	InvoiceToken   string
	UserID         string
	Month          uint
	Year           uint
	Type           uint
	Domain         string
	Subdomain      string
	Description    string
	ProposalURL    string
	Labor          uint
	Expenses       uint
	ContractorRate uint
	PublicKey      string
	ExchangeRate   uint
	SubRate        uint
	SubUser        string
}

/*
// This function must be called within a transaction.
func createCmsTables(tx *gorm.DB) error {
	log.Tracef("createCmsTables")

	// Create cms tables
	if !tx.HasTable(tableNameInvoice) {
		err := tx.CreateTable(&Invoice{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableNameLineItem) {
		err := tx.CreateTable(&LineItem{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableNameInvoiceChange) {
		err := tx.CreateTable(&InvoiceChange{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableNameExchangeRate) {
		err := tx.CreateTable(&ExchangeRate{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableNamePayments) {
		err := tx.CreateTable(&Payments{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableNameDCC) {
		err := tx.CreateTable(&DCC{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableNameVersions) {
		err := tx.CreateTable(&Version{}).Error
		if err != nil {
			return err
		}
	}

	var v Version
	err := tx.Where("id = ?", cacheID).
		Find(&v).
		Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = tx.Create(
			&Version{
				ID:        cacheID,
				Version:   cmsVersion,
				Timestamp: time.Now().Unix(),
			}).Error
		return err
	}
	return nil
}
*/
// Setup calls the tables creation function to ensure the database is prepared for use.
func (m *mysql) Setup() error {
	return nil
}

// Build drops all existing tables from the records cache, recreates them, then
// builds the records cache using the passed in records.
func (m *mysql) Build(dbInvs []database.Invoice, dbDCCs []database.DCC) error {
	return nil
}

// Update existing payment.
//
// UpdatePayments satisfies the database interface.
func (m *mysql) UpdatePayments(dbPayments *database.Payments) error {

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

	// CALL updatePayments func here

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

// PaymentsByAddress returns payments row that has the matching Address.
func (m *mysql) PaymentsByAddress(address string) (*database.Payments, error) {
	return nil, nil
}

// PaymentsByStatus returns all payments rows that match the given status.
func (m *mysql) PaymentsByStatus(status uint) ([]database.Payments, error) {
	return nil, nil
}

// Create new dcc.
//
// NewDCC satisfies the database interface.
func (m *mysql) NewDCC(dbDCC *database.DCC) error {

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

	// CALL newDCC func here

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

// Update existing dcc.
//
// UpdateDCC satisfies the database interface.
func (m *mysql) UpdateDCC(dbDCC *database.DCC) error {

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

// DCCByToken Return DCC by its token.
func (m *mysql) DCCByToken(token string) (*database.DCC, error) {
	return nil, nil
}

// DCCsByStatus Return DCCs by status.
func (m *mysql) DCCsByStatus(status int) ([]*database.DCC, error) {
	return nil, nil
}

// DCCsAll Returns all DCCs regardless of status.
func (m *mysql) DCCsAll() ([]*database.DCC, error) {
	return nil, nil
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
