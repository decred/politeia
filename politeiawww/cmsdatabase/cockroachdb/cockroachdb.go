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

	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

const (
	cacheID    = "cms"
	cmsVersion = "2"

	// Database table names
	tableNameVersions      = "versions"
	tableNameInvoice       = "invoices"
	tableNameLineItem      = "line_items"
	tableNameInvoiceChange = "invoice_changes"
	tableNameExchangeRate  = "exchange_rates"
	tableNamePayments      = "payments"
	tableNameDCC           = "dcc"

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

// RemoveLineItem deletes an existing invoice line items from the database.
func (c *cockroachdb) RemoveInvoiceLineItems(invoiceToken string) error {
	log.Debugf("RemoveInvoiceLineItems: %v", invoiceToken)

	return c.recordsdb.Where("invoice_token = ?", invoiceToken).Delete(&LineItem{}).Error
}

// Return all invoices by userid
func (c *cockroachdb) InvoicesByUserID(userid string) ([]database.Invoice, error) {
	log.Tracef("InvoicesByUserID")

	// Lookup the latest version of each invoice
	query := `SELECT *
            FROM invoices a
            LEFT OUTER JOIN invoices b
              ON a.token = b.token
              AND a.version < b.version
              WHERE b.token IS NULL
              AND a.user_id = ?`
	rows, err := c.recordsdb.Raw(query, userid).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	for rows.Next() {
		var i Invoice
		err := c.recordsdb.ScanRows(rows, &i)
		if err != nil {
			return nil, err
		}
		invoices = append(invoices, i)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(invoices))
	for _, r := range invoices {
		keys = append(keys, r.Key)
	}
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Where(keys).
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

	invoice := Invoice{}
	err := c.recordsdb.
		Where("token = ?", token).
		Order("version desc").
		Limit(1).
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Find(&invoice).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrInvoiceNotFound
		}
		return nil, err
	}

	return DecodeInvoice(&invoice)
}

// InvoiceByTokenVersion Return invoice by its token and version
func (c *cockroachdb) InvoiceByTokenVersion(token string, version string) (*database.Invoice, error) {
	log.Debugf("InvoiceByTokenVersion: %v", token)

	invoice := Invoice{}
	err := c.recordsdb.
		Where("key = ?", token+version).
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Find(&invoice).Error
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

	// Lookup the latest version of each invoice
	query := `SELECT *
            FROM invoices a
            LEFT OUTER JOIN invoices b
              ON a.token = b.token
              AND a.version < b.version
              WHERE b.token IS NULL
              AND month = ? AND year = ? AND status = ?`
	rows, err := c.recordsdb.Raw(query, month, year, status).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	for rows.Next() {
		var i Invoice
		err := c.recordsdb.ScanRows(rows, &i)
		if err != nil {
			return nil, err
		}
		invoices = append(invoices, i)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(invoices))
	for _, r := range invoices {
		keys = append(keys, r.Key)
	}
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Where(keys).
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

	// Lookup the latest version of each invoice
	query := `SELECT *
            FROM invoices a
            LEFT OUTER JOIN invoices b
              ON a.token = b.token
              AND a.version < b.version
              WHERE b.token IS NULL
              AND a.month = ? AND a.year = ?`
	rows, err := c.recordsdb.Raw(query, month, year).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	for rows.Next() {
		var i Invoice
		err := c.recordsdb.ScanRows(rows, &i)
		if err != nil {
			return nil, err
		}
		invoices = append(invoices, i)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(invoices))
	for _, r := range invoices {
		keys = append(keys, r.Key)
	}
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Where(keys).
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

	// Lookup the latest version of each invoice
	query := `SELECT *
            FROM invoices a
            LEFT OUTER JOIN invoices b
              ON a.token = b.token
              AND a.version < b.version
              WHERE a.status = ?`
	rows, err := c.recordsdb.Raw(query, status).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	for rows.Next() {
		var i Invoice
		err := c.recordsdb.ScanRows(rows, &i)
		if err != nil {
			return nil, err
		}
		invoices = append(invoices, i)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	// Compile a list of record primary keys
	keys := make([]string, 0, len(invoices))
	for _, v := range invoices {
		keys = append(keys, v.Key)
	}

	// Lookup files and metadata streams for each of the
	// previously queried records.
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Where(keys).
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
	// Lookup the latest version of each invoice
	query := `SELECT *
            FROM invoices a
            LEFT OUTER JOIN invoices b
              ON a.token = b.token
              AND a.version < b.version`
	rows, err := c.recordsdb.Raw(query).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	for rows.Next() {
		var i Invoice
		err := c.recordsdb.ScanRows(rows, &i)
		if err != nil {
			return nil, err
		}
		invoices = append(invoices, i)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	// Compile a list of record primary keys
	keys := make([]string, 0, len(invoices))
	for _, v := range invoices {
		keys = append(keys, v.Key)
	}

	// Lookup files and metadata streams for each of the
	// previously queried records.
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Where(keys).
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

	// Lookup the latest version of each invoice
	query := `SELECT *
            FROM invoices a
            LEFT OUTER JOIN invoices b
              ON a.token = b.token
              AND a.version < b.version
              WHERE b.token IS NULL
              AND a.payment_address = ?`
	rows, err := c.recordsdb.Raw(query, address).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	invoices := make([]Invoice, 0, 1024) // PNOOMA
	for rows.Next() {
		var i Invoice
		err := c.recordsdb.ScanRows(rows, &i)
		if err != nil {
			return nil, err
		}
		invoices = append(invoices, i)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	// Compile a list of record primary keys
	keys := make([]string, 0, len(invoices))
	for _, v := range invoices {
		keys = append(keys, v.Key)
	}

	// Lookup files and metadata streams for each of the
	// previously queried records.
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Changes").
		Preload("Payments").
		Where(keys).
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

// InvoicesByDateRangeStatus takes a start and end time (in Unix seconds) and returns
// all invoices with the included status.  This uses the
// invoice_changes table to discover the token to look up the correct line items.
func (c *cockroachdb) InvoicesByDateRangeStatus(start, end int64, status int) ([]database.Invoice, error) {
	log.Debugf("InvoicesByDateRangeStatus: %v %v", time.Unix(start, 0),
		time.Unix(end, 0))
	// Get all invoice changes of given status within date range.
	invoiceChanges := make([]InvoiceChange, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("new_status = ? AND "+
			"timestamp BETWEEN ? AND ?",
			status,
			time.Unix(start, 0),
			time.Unix(end, 0)).
		Find(&invoiceChanges).
		Error
	if err != nil {
		return nil, err
	}
	tokens := make([]string, 0, len(invoiceChanges))
	for _, r := range invoiceChanges {
		tokens = append(tokens, r.InvoiceToken)
	}
	invoices := make([]Invoice, 0, len(tokens))
	// Using all invoice tokens from the results of the query above, ask for all
	// invoices that match those tokens.
	dbInvoices := make([]database.Invoice, 0, len(tokens))
	err = c.recordsdb.
		Preload("LineItems").
		Preload("Payments").
		Preload("Changes").
		Where(tokens).
		Find(&invoices).
		Error
	if err != nil {
		return nil, err
	}
	for _, vv := range invoices {
		inv, err := DecodeInvoice(&vv)
		if err != nil {
			return nil, err
		}
		dbInvoices = append(dbInvoices, *inv)
	}
	return dbInvoices, nil
}

// InvoicesByDateRange takes a start and end time (in Unix seconds) and returns
// all invoices.  This uses the
// invoice_changes table to discover the token to look up the correct line items.
func (c *cockroachdb) InvoicesByDateRange(start, end int64) ([]database.Invoice, error) {
	log.Debugf("InvoicesByDateRange: %v %v", time.Unix(start, 0),
		time.Unix(end, 0))
	// Get all invoice changes of NEW status within date range.
	invoiceChanges := make([]InvoiceChange, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("new_status = ? AND"+
			"timestamp BETWEEN ? AND ?",
			v1.InvoiceStatusNew,
			time.Unix(start, 0),
			time.Unix(end, 0)).
		Find(&invoiceChanges).
		Error
	if err != nil {
		return nil, err
	}
	tokens := make([]string, 0, len(invoiceChanges))
	for _, r := range invoiceChanges {
		tokens = append(tokens, r.InvoiceToken)
	}
	invoices := make([]Invoice, 0, len(tokens))
	// Using all invoice tokens from the results of the query above, ask for all
	// invoices that match those tokens.
	dbInvoices := make([]database.Invoice, 0, len(tokens))
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
	for _, vv := range invoices {
		inv, err := DecodeInvoice(&vv)
		if err != nil {
			return nil, err
		}
		dbInvoices = append(dbInvoices, *inv)
	}
	return dbInvoices, nil
}

// InvoicesByLineItemsProposalToken takes a proposal token as an argument and
// returns all invoices that have line items corresponding with that token.
// All line items that are not considered relevant to the proposal token will
// be omitted.
func (c *cockroachdb) InvoicesByLineItemsProposalToken(token string) ([]database.Invoice, error) {
	log.Debugf("InvoicesByLineItemsProposalToken: %v", token)
	// Get all line items with proposal token
	query := `SELECT 
              invoices.month, 
              invoices.year, 
              invoices.user_id,
              invoices.public_key,
              invoices.contractor_rate,
              invoices.exchange_rate,
              line_items.invoice_token,
              line_items.type,
              line_items.domain,
              line_items.subdomain,
              line_items.description,
              line_items.proposal_url,
              line_items.labor,
              line_items.expenses,
              line_items.contractor_rate AS sub_rate
            FROM invoices
            LEFT OUTER JOIN invoices b
              ON invoices.token = b.token
              AND invoices.version < b.version
            INNER JOIN line_items
              ON invoices.token = line_items.invoice_token
              WHERE line_items.proposal_url = ? AND invoices.status = ?`
	rows, err := c.recordsdb.Raw(query, token, int(v1.InvoiceStatusPaid)).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	matching := make([]MatchingLineItems, 0, 1024)
	for rows.Next() {
		var i MatchingLineItems
		err := c.recordsdb.ScanRows(rows, &i)
		if err != nil {
			return nil, err
		}
		matching = append(matching, i)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return convertMatchingLineItemToInvoices(matching), nil
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
	if err == gorm.ErrRecordNotFound {
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

func (c *cockroachdb) dropTables(tx *gorm.DB) error {
	// Drop record tables
	err := tx.DropTableIfExists(tableNameInvoice, tableNameInvoiceChange,
		tableNameLineItem, tableNamePayments, tableNameDCC).Error
	if err != nil {
		return err
	}

	// Remove cms version record
	return tx.Delete(&Version{
		ID: cacheID,
	}).Error
}

// build the records cache using the passed in records.
//
// This function cannot be called using a transaction because it could
// potentially exceed cockroachdb's transaction size limit.
func (c *cockroachdb) build(invoices []Invoice, dccs []DCC) error {
	log.Tracef("build")

	// Drop record tables
	tx := c.recordsdb.Begin()
	err := c.dropTables(tx)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("drop tables: %v", err)
	}
	err = tx.Commit().Error
	if err != nil {
		return err
	}

	// Create record tables
	tx = c.recordsdb.Begin()
	err = createCmsTables(tx)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("create tables: %v", err)
	}
	err = tx.Commit().Error
	if err != nil {
		return err
	}

	for _, i := range invoices {
		err := c.recordsdb.Create(&i).Error
		if err != nil {
			log.Debugf("create invoice failed on '%v'", i)
			return fmt.Errorf("create invoice: %v", err)
		}
	}

	for _, d := range dccs {
		err := c.recordsdb.Create(&d).Error
		if err != nil {
			log.Debugf("create dcc failed on '%v'", d)
			return fmt.Errorf("create dcc: %v", err)
		}
	}

	return nil
}

// Build drops all existing tables from the records cache, recreates them, then
// builds the records cache using the passed in records.
func (c *cockroachdb) Build(dbInvs []database.Invoice, dbDCCs []database.DCC) error {
	log.Tracef("Build")

	c.Lock()
	defer c.Unlock()

	if c.shutdown {
		return database.ErrShutdown
	}

	log.Infof("Building records cache")
	invoices := make([]Invoice, 0, len(dbInvs))
	for _, dbInv := range dbInvs {
		inv := EncodeInvoice(&dbInv)
		invoices = append(invoices, *inv)
	}
	dccs := make([]DCC, 0, len(dbDCCs))
	for _, dbDCC := range dbDCCs {
		dcc := encodeDCC(&dbDCC)
		dccs = append(dccs, *dcc)
	}
	// Build the records cache. This is not run using a
	// transaction because it could potentially exceed
	// cockroachdb's transaction size limit.
	err := c.build(invoices, dccs)
	if err != nil {
		// Remove the version record. This will
		// force a rebuild on the next start up.
		err1 := c.recordsdb.Delete(&Version{
			ID: cacheID,
		}).Error
		if err1 != nil {
			panic("the cache is out of sync and will not rebuild" +
				"automatically; a rebuild must be forced")
		}
	}

	return err
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

	// Return an error if the version record is not found or
	// if there is a version mismatch, but also return the
	// cache context so that the cache can be built/rebuilt.
	if !c.recordsdb.HasTable(tableNameVersions) {
		log.Debugf("table '%v' does not exist", tableNameVersions)
		return c, database.ErrNoVersionRecord
	}

	var v Version
	err = c.recordsdb.
		Where("id = ?", cacheID).
		Find(&v).
		Error
	if err == gorm.ErrRecordNotFound {
		log.Debugf("version record not found for ID '%v'", cacheID)
		err = database.ErrNoVersionRecord
	} else if v.Version != cmsVersion {
		log.Debugf("version mismatch for ID '%v': got %v, want %v",
			cacheID, v.Version, cmsVersion)
		err = database.ErrWrongVersion
	}

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

	payments := Payments{}
	err := c.recordsdb.
		Where("address = ?", address).
		Find(&payments).Error
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

// Create new dcc.
//
// NewDCC satisfies the database interface.
func (c *cockroachdb) NewDCC(dbDCC *database.DCC) error {
	dcc := encodeDCC(dbDCC)

	log.Debugf("NewDCC: %v", dcc.Token)
	return c.recordsdb.Create(dcc).Error
}

// Update existing dcc.
//
// UpdateDCC satisfies the database interface.
func (c *cockroachdb) UpdateDCC(dbDCC *database.DCC) error {
	dcc := encodeDCC(dbDCC)

	log.Debugf("UpdateDCC: %v", dcc.Token)

	return c.recordsdb.Save(dcc).Error
}

// DCCByToken Return DCC by its token.
func (c *cockroachdb) DCCByToken(token string) (*database.DCC, error) {
	log.Debugf("DCCByToken: %v", token)

	dcc := DCC{
		Token: token,
	}
	err := c.recordsdb.
		Find(&dcc).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrDCCNotFound
		}
		return nil, err
	}

	return decodeDCC(&dcc), nil
}

// DCCsByStatus Return DCCs by status.
func (c *cockroachdb) DCCsByStatus(status int) ([]*database.DCC, error) {
	log.Debugf("DCCsByStatus: %v", status)

	dccs := make([]DCC, 0, 1048)
	err := c.recordsdb.
		Where("status = ?", status).
		Find(&dccs).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrDCCNotFound
		}
		return nil, err
	}

	dbDCCs := make([]*database.DCC, 0, 1048)
	for _, v := range dccs {
		dbDCCs = append(dbDCCs, decodeDCC(&v))
	}
	return dbDCCs, nil
}

// DCCsAll Returns all DCCs regardless of status.
func (c *cockroachdb) DCCsAll() ([]*database.DCC, error) {
	log.Debugf("DCCsAll:")

	dccs := make([]DCC, 0, 1048)
	err := c.recordsdb.
		Find(&dccs).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrDCCNotFound
		}
		return nil, err
	}

	dbDCCs := make([]*database.DCC, 0, 1048)
	for _, v := range dccs {
		dbDCCs = append(dbDCCs, decodeDCC(&v))
	}
	return dbDCCs, nil
}
