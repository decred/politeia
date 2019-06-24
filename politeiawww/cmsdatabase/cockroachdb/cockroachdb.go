// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/decred/politeia/decredplugin"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

const (
	cacheID    = "cms"
	cmsVersion = "1"

	// Database table names
	tableNameInvoice       = "invoices"
	tableNameLineItem      = "line_items"
	tableNameInvoiceChange = "invoice_changes"
	tableNameExchangeRate  = "exchange_rates"
	tableNamePayments      = "payments"

	userPoliteiawww = "politeiawww" // cmsdb user (read/write access)
)

// cockroachdb implements the cache interface.
type cockroachdb struct {
	sync.RWMutex
	shutdown  bool     // Backend is shutdown
	recordsdb *gorm.DB // Database context
}

// Create new invoice.
//
// CreateInvoice satisfies the database interface.
func (c *cockroachdb) NewInvoice(dbInvoice *database.Invoice) error {
	invoice := EncodeInvoice(dbInvoice)

	log.Debugf("CreateInvoice: %v", invoice.Token)
	return c.recordsdb.Create(invoice).Error
}

// Update existing invoice.
//
// UpdateInvoice satisfies the database interface.
func (c *cockroachdb) UpdateInvoice(dbInvoice *database.Invoice) error {
	invoice := EncodeInvoice(dbInvoice)

	log.Debugf("UpdateInvoice: %v", invoice.Token)

	return c.recordsdb.Save(invoice).Error
}

// Return all invoices by userid
func (c *cockroachdb) InvoicesByUserID(userid string) ([]database.Invoice, error) {
	log.Tracef("InvoicesByUserID")

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("user_id = ?", userid).
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}

	tokens := make([]string, 0, len(invoices))
	for _, r := range invoices {
		tokens = append(tokens, r.Token)
	}
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Where(tokens).
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}

	dbInvoices := make([]database.Invoice, 0, len(invoices))
	for _, v := range invoices {
		dbInvoice, err := DecodeInvoice(&v)
		if err != nil {
			return nil, err
		}
		dbInvoices = append(dbInvoices, *dbInvoice)
	}
	return dbInvoices, nil
}

// InvoiceByToken Return invoice by its token.
func (c *cockroachdb) InvoiceByToken(token string) (*database.Invoice, error) {
	log.Debugf("InvoiceByToken: %v", token)

	invoice := Invoice{
		Token: token,
	}
	err := c.recordsdb.Find(&invoice).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrInvoiceNotFound
		}
		return nil, err
	}

	return DecodeInvoice(&invoice)
}

// InvoicesByMonthYearStatus returns all invoices by month year and status
func (c *cockroachdb) InvoicesByMonthYearStatus(month, year uint16, status int) ([]database.Invoice, error) {
	log.Tracef("InvoicesByMonthYearStatus")

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("month = ? AND year = ? AND status = ?", month, year, status).
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}

	tokens := make([]string, 0, len(invoices))
	for _, r := range invoices {
		tokens = append(tokens, r.Token)
	}
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Where(tokens).
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}

	dbInvoices := make([]database.Invoice, 0, len(invoices))
	for _, v := range invoices {
		dbInvoice, err := DecodeInvoice(&v)
		if err != nil {
			return nil, err
		}
		dbInvoices = append(dbInvoices, *dbInvoice)
	}
	return dbInvoices, nil
}

// InvoicesByMonthYear returns all invoices by month/year
func (c *cockroachdb) InvoicesByMonthYear(month, year uint16) ([]database.Invoice, error) {
	log.Tracef("InvoicesByMonthYear")

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("month = ? AND year = ?", month, year).
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}

	tokens := make([]string, 0, len(invoices))
	for _, r := range invoices {
		tokens = append(tokens, r.Token)
	}
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Where(tokens).
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}

	dbInvoices := make([]database.Invoice, 0, len(invoices))
	for _, v := range invoices {
		dbInvoice, err := DecodeInvoice(&v)
		if err != nil {
			return nil, err
		}
		dbInvoices = append(dbInvoices, *dbInvoice)
	}
	return dbInvoices, nil
}

// InvoicesByStatus returns all invoices by status
func (c *cockroachdb) InvoicesByStatus(status int) ([]database.Invoice, error) {
	log.Tracef("InvoicesByStatus")

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("status = ?", status).
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}

	tokens := make([]string, 0, len(invoices))
	for _, r := range invoices {
		tokens = append(tokens, r.Token)
	}
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Where(tokens).
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}

	dbInvoices := make([]database.Invoice, 0, len(invoices))
	for _, v := range invoices {
		dbInvoice, err := DecodeInvoice(&v)
		if err != nil {
			return nil, err
		}
		dbInvoices = append(dbInvoices, *dbInvoice)
	}
	return dbInvoices, nil
}

// InvoicesAll returns all invoices
func (c *cockroachdb) InvoicesAll() ([]database.Invoice, error) {
	log.Tracef("InvoicesAll")

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}

	tokens := make([]string, 0, len(invoices))
	for _, r := range invoices {
		tokens = append(tokens, r.Token)
	}
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Where(tokens).
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}

	dbInvoices := make([]database.Invoice, 0, len(invoices))
	for _, v := range invoices {
		dbInvoice, err := DecodeInvoice(&v)
		if err != nil {
			return nil, err
		}
		dbInvoices = append(dbInvoices, *dbInvoice)
	}
	return dbInvoices, nil
}

// InvoicesByAddress return invoices by its payment address.
func (c *cockroachdb) InvoicesByAddress(address string) ([]database.Invoice, error) {
	log.Debugf("InvoiceByAddress: %v", address)

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("payment_address = ?", address).
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}

	dbInvoices := make([]database.Invoice, 0, len(invoices))
	for _, v := range invoices {
		dbInvoice, err := DecodeInvoice(&v)
		if err != nil {
			return nil, err
		}
		dbInvoices = append(dbInvoices, *dbInvoice)
	}

	return dbInvoices, nil
}

// Create new exchange rate.
//
// NewExchangeRate satisfies the database interface.
func (c *cockroachdb) NewExchangeRate(dbExchangeRate *database.ExchangeRate) error {
	exchRate := encodeExchangeRate(dbExchangeRate)

	log.Debugf("NewExchangeRate: %v %v", exchRate.Month, exchRate.Year)
	return c.recordsdb.Create(exchRate).Error
}

// ExchangeRate returns exchange rate by month/year
func (c *cockroachdb) ExchangeRate(month, year int) (*database.ExchangeRate, error) {
	log.Tracef("ExchangeRate")

	exchangeRate := ExchangeRate{}
	err := c.recordsdb.
		Where("month = ? AND year = ?", month, year).
		Find(&exchangeRate).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrExchangeRateNotFound
		}
		return nil, err
	}

	return decodeExchangeRate(exchangeRate), nil
}

// LineItemsByDateRange takes a start and end time (in Unix seconds) and returns
// all line items that have been paid in that range.  This uses the
// invoice_changes table to discover the token to look up the correct line items.
func (c *cockroachdb) LineItemsByDateRange(start, end int64) ([]database.LineItem, error) {
	log.Debugf("LineItemsByDateRange: %v %v", time.Unix(start, 0),
		time.Unix(end, 0))
	// Get all invoice changes of PAID status within date range.
	invoiceChanges := make([]InvoiceChange, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("timestamp BETWEEN ? AND ?",
			time.Unix(start, 0),
			time.Unix(end, 0)).
		Find(&invoiceChanges).
		Error
	if err != nil {
		return nil, err
	}

	// Using all invoice tokens from the results of the query above, ask for all
	// line items that match those tokens.
	dbLineItems := make([]database.LineItem, 0, 1024)
	for _, v := range invoiceChanges {
		lineItems := make([]LineItem, 0, 1024)
		err = c.recordsdb.
			Where("invoice_token = ?", v.InvoiceToken).
			Find(&lineItems).
			Error
		if err != nil {
			return nil, err
		}
		for _, vv := range lineItems {
			dbLineItem := DecodeInvoiceLineItem(&vv)
			dbLineItems = append(dbLineItems, *dbLineItem)
		}
	}

	return dbLineItems, nil
}

// Close satisfies the database interface.
func (c *cockroachdb) Close() error {
	return c.recordsdb.Close()
}

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
	return nil
}

//
// This function must be called within a transaction.
func (c *cockroachdb) build(tx *gorm.DB, ir *decredplugin.InventoryReply) error {
	log.Tracef("cms build")

	// Create the database tables
	err := createCmsTables(tx)
	if err != nil {
		return fmt.Errorf("createCmsTables: %v", err)
	}

	// pull Inventory from d then rebuild invoice database
	return nil
}

// Build drops all existing decred plugin tables from the database, recreates
// them, then uses the passed in inventory payload to build the decred plugin
// cache.
func (c *cockroachdb) Build(payload string) error {
	log.Tracef("invoice Build")

	// Decode the payload
	ir, err := decredplugin.DecodeInventoryReply([]byte(payload))
	if err != nil {
		return fmt.Errorf("DecodeInventoryReply: %v", err)
	}

	// Drop all decred plugin tables
	err = c.recordsdb.DropTableIfExists(tableNameInvoice, tableNameLineItem).Error
	if err != nil {
		return fmt.Errorf("drop invoice tables failed: %v", err)
	}

	// Build the decred plugin cache from scratch
	tx := c.recordsdb.Begin()
	err = c.build(tx, ir)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// Setup calls the tables creation function to ensure the database is prepared for use.
func (c *cockroachdb) Setup() error {
	tx := c.recordsdb.Begin()
	err := createCmsTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func buildQueryString(user, rootCert, cert, key string) string {
	v := url.Values{}
	v.Set("sslmode", "require")
	v.Set("sslrootcert", filepath.Clean(rootCert))
	v.Set("sslcert", filepath.Join(cert))
	v.Set("sslkey", filepath.Join(key))
	return v.Encode()
}

// New returns a new cockroachdb context that contains a connection to the
// specified database that was made using the politeiawww user and the passed
// in certificates.
func New(host, net, rootCert, cert, key string) (*cockroachdb, error) {
	log.Tracef("New: %v %v %v %v %v", host, net, rootCert, cert, key)

	// Connect to database
	dbName := cacheID + "_" + net
	h := "postgresql://" + userPoliteiawww + "@" + host + "/" + dbName
	u, err := url.Parse(h)
	if err != nil {
		return nil, fmt.Errorf("parse url '%v': %v", h, err)
	}

	qs := buildQueryString(u.User.String(), rootCert, cert, key)
	addr := u.String() + "?" + qs
	db, err := gorm.Open("postgres", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to database '%v': %v", addr, err)
	}

	// Create context
	c := &cockroachdb{
		recordsdb: db,
	}

	// Disable gorm logging. This prevents duplicate errors from
	// being printed since we handle errors manually.
	c.recordsdb.LogMode(false)

	// Disable automatic table name pluralization. We set table
	// names manually.
	c.recordsdb.SingularTable(true)

	return c, err
}

// Update existing payment.
//
// UpdatePayments satisfies the database interface.
func (c *cockroachdb) UpdatePayments(dbPayments *database.Payments) error {
	payments := encodePayments(dbPayments)

	log.Debugf("UpdatePayments: %v", payments.InvoiceToken)

	return c.recordsdb.Save(payments).Error
}

// PaymentsByAddress returns payments row that has the matching Address.
func (c *cockroachdb) PaymentsByAddress(address string) (*database.Payments, error) {
	log.Debugf("PaymentsByAddress: %v", address)

	payments := Payments{
		Address: address,
	}
	err := c.recordsdb.Find(&payments).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrInvoiceNotFound
		}
		return nil, err
	}
	dbPayments := decodePayment(&payments)
	return &dbPayments, nil
}

// PaymentsByStatus returns all payments rows that match the given status.
func (c *cockroachdb) PaymentsByStatus(status uint) ([]database.Payments, error) {
	log.Debugf("PaymentsByStatus: %v", status)

	payments := make([]Payments, 0, 1048)
	err := c.recordsdb.
		Where("status = ?", status).
		Find(&payments).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrInvoiceNotFound
		}
		return nil, err
	}
	dbPayments := make([]database.Payments, 0, 1048)
	for _, v := range payments {
		dbPayments = append(dbPayments, decodePayment(&v))
	}
	return dbPayments, nil
}
