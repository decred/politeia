package testcmsdb

import (
	"sync"

	cmsdb "github.com/decred/politeia/politeiawww/cmsdatabase"
)

type testcmsdb struct {
	sync.RWMutex
	shutdown bool // Backend is shutdown

	records map[string]cmsdb.Invoice // [token]invoice
}

// ExchangeRate satisfies the db interface and is used in testing.
func (c *testcmsdb) ExchangeRate(month, year int) (*cmsdb.ExchangeRate, error) {
	// Values used in testing
	return &cmsdb.ExchangeRate{
		Month:        uint(month),
		Year:         uint(year),
		ExchangeRate: 1651,
	}, nil
}

// InvoicesByAddress satisfies the db interface and is used in testing.
func (c *testcmsdb) InvoicesByAddress(addr string) ([]cmsdb.Invoice, error) {
	c.RLock()
	defer c.RUnlock()

	invoices := make([]cmsdb.Invoice, 0, 1024)
	for _, v := range c.records {
		if v.PaymentAddress == addr {
			invoices = append(invoices, v)
		}
	}

	return invoices, nil
}

// NewInvoice is a stub to satisfy the db interface.
func (c *testcmsdb) NewInvoice(i *cmsdb.Invoice) error {
	return nil
}

// UpdateInvoice is a stub to satisfy the db interface.
func (c *testcmsdb) UpdateInvoice(i *cmsdb.Invoice) error {
	return nil
}

// InvoicesByUserID is a stub to satisfy the db interface.
func (c *testcmsdb) InvoicesByUserID(s string) ([]cmsdb.Invoice, error) {
	return make([]cmsdb.Invoice, 0), nil
}

// InvoiceByToken satisfies the db interface and is used in testing.
func (c *testcmsdb) InvoiceByToken(t string) (*cmsdb.Invoice, error) {
	c.RLock()
	defer c.RUnlock()

	invoice, ok := c.records[t]
	if !ok {
		return nil, cmsdb.ErrInvoiceNotFound
	}

	return &invoice, nil
}

// InvoicesByMonthYearStatus is a stub to satisfy the db interface.
func (c *testcmsdb) InvoicesByMonthYearStatus(m uint16, y uint16, s int) ([]cmsdb.Invoice, error) {
	return make([]cmsdb.Invoice, 0), nil
}

// InvoicesByMonthYear is a stub to satisfy the db interface.
func (c *testcmsdb) InvoicesByMonthYear(m uint16, y uint16) ([]cmsdb.Invoice, error) {
	return make([]cmsdb.Invoice, 0), nil
}

// InvoicesByStatus is a stub to satisfy the db interface.
func (c *testcmsdb) InvoicesByStatus(s int) ([]cmsdb.Invoice, error) {
	return make([]cmsdb.Invoice, 0), nil
}

// InvoicesAll is a stub to satisfy the db interface.
func (c *testcmsdb) InvoicesAll() ([]cmsdb.Invoice, error) {
	return make([]cmsdb.Invoice, 0), nil
}

// InvoicesByDateRangeStatus is a stub to satisfy the db interface.
func (c *testcmsdb) InvoicesByDateRangeStatus(d, m int64, y int) ([]*cmsdb.Invoice, error) {
	return make([]*cmsdb.Invoice, 0), nil
}

// LineItemsByDateRange is a stub to satisfy the db interface.
func (c *testcmsdb) LineItemsByDateRange(m int64, y int64) ([]cmsdb.LineItem, error) {
	return make([]cmsdb.LineItem, 0), nil
}

// NewExchangeRate is a stub to satisfy the db interface.
func (c *testcmsdb) NewExchangeRate(*cmsdb.ExchangeRate) error {
	return nil
}

// UpdatePayments is a stub to satisfy the db interface.
func (c *testcmsdb) UpdatePayments(*cmsdb.Payments) error {
	return nil
}

// PaymentsByAddress is a stub to satisfy the db interface.
func (c *testcmsdb) PaymentsByAddress(addr string) (*cmsdb.Payments, error) {
	return &cmsdb.Payments{}, nil
}

// PaymentsByStatus is a stub to satisfy the db interface.
func (c *testcmsdb) PaymentsByStatus(s uint) ([]cmsdb.Payments, error) {
	return make([]cmsdb.Payments, 0), nil
}

// NewDCC is a stub to satisfy the db interface.
func (c *testcmsdb) NewDCC(dcc *cmsdb.DCC) error {
	return nil
}

// UpdateDCC is a stub to satisfy the db interface.
func (c *testcmsdb) UpdateDCC(dcc *cmsdb.DCC) error {
	return nil
}

// DCCByToken is a stub to satisfy the db interface.
func (c *testcmsdb) DCCByToken(s string) (*cmsdb.DCC, error) {
	return &cmsdb.DCC{}, nil
}

// DCCByStatus is a stub to satisfy the db interface.
func (c *testcmsdb) DCCsByStatus(s int) ([]*cmsdb.DCC, error) {
	return make([]*cmsdb.DCC, 0), nil
}

// DCCsAll is a stub to satisfy the db interface.
func (c *testcmsdb) DCCsAll() ([]*cmsdb.DCC, error) {
	return make([]*cmsdb.DCC, 0), nil
}

// Setup is a stub to satisfy the db interface.
func (c *testcmsdb) Setup() error {
	return nil
}

// Build is a stub to satisfy the db interface.
func (c *testcmsdb) Build(s string) error {
	return nil
}

// Close is a stub to satisfy the db interface.
func (c *testcmsdb) Close() error {
	return nil
}

func New() *testcmsdb {
	return &testcmsdb{
		shutdown: false,
		records:  make(map[string]cmsdb.Invoice),
	}
}
