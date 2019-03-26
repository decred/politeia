// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/decredplugin"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

const (
	cacheID    = "cms"
	cmsVersion = "1"

	// Database table names
	tableNameInvoice  = "invoices"
	tableNameLineItem = "line_items"

	UserCMSDB = "invoices_cmsdb" // cmsdb user (read/write access)
)

// cockroachdb implements the cache interface.
type cockroachdb struct {
	sync.RWMutex
	shutdown  bool     // Backend is shutdown
	recordsdb *gorm.DB // Database context
}

// Create new invoice.
//
// CreateInvoice satisfies the backend interface.
func (c *cockroachdb) NewInvoice(dbInvoice *database.Invoice) error {
	invoice := EncodeInvoice(dbInvoice)

	log.Debugf("CreateInvoice: %v", invoice.Token)
	return c.recordsdb.Create(invoice).Error
}

// Update existing invoice.
//
// CreateInvoice satisfies the backend interface.
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

// Return invoice by its token.
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

// Return all invoices by month year and status
func (c *cockroachdb) InvoicesByMonthYearStatus(month, year uint16, status int) ([]database.Invoice, error) {
	log.Tracef("InvoicesByMonthYearStatus")

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("month = ? && year = ? && status == ?", month, year, status).
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

// Return all invoices by month/year
func (c *cockroachdb) InvoicesByMonthYear(month, year uint16) ([]database.Invoice, error) {
	log.Tracef("InvoicesByMonthYear")

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("month = ? && year = ?", month, year).
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

// Return all invoices by status
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

// Return all invoices
func (c *cockroachdb) InvoicesAll() ([]database.Invoice, error) {
	log.Tracef("InvoicesAll")

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	err := c.recordsdb.
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

// Close satisfies the backend interface.
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
	v.Set("ssl", "true")
	v.Set("sslmode", "require")
	v.Set("sslrootcert", filepath.Clean(rootCert))
	v.Set("sslcert", filepath.Join(cert))
	v.Set("sslkey", filepath.Join(key))
	return v.Encode()
}

// New returns a new cockroachdb context that contains a connection to the
// specified database that was made using the passed in user and certificates.
func New(user, host, net, rootCert, cert, key string) (*cockroachdb, error) {
	log.Tracef("New: %v %v %v %v %v %v", user, host, net, rootCert, cert, key)

	// Connect to database
	dbName := cacheID + "_" + net
	h := "postgresql://" + user + "@" + host + "/" + dbName
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
