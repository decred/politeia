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
	"github.com/decred/politeia/politeiad/cache"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

const (
	cacheID      = "records"
	cacheVersion = "1"

	// Database table names
	tableVersions        = "versions"
	tableRecords         = "records"
	tableMetadataStreams = "metadata_streams"
	tableFiles           = "files"

	// Database users
	UserPoliteiad   = "records_politeiad"   // politeiad user (read/write access)
	UserPoliteiawww = "records_politeiawww" // politeiawww user (read access)
)

// cockroachdb implements the cache interface.
type cockroachdb struct {
	sync.RWMutex
	shutdown  bool                          // Backend is shutdown
	recordsdb *gorm.DB                      // Database context
	plugins   map[string]cache.PluginDriver // [pluginID]PluginDriver
}

// NewRecord creates a new entry in the database for the passed in record.
func (c *cockroachdb) NewRecord(cr cache.Record) error {
	log.Tracef("NewRecord: %v", cr.CensorshipRecord.Token)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return cache.ErrShutdown
	}

	r := convertRecordFromCache(cr)
	return c.recordsdb.Create(&r).Error
}

// recordVersion gets the specified version of a record from the database.
// This function has a database parameter so that it can be called inside of
// a transaction when required.
func (c *cockroachdb) recordVersion(db *gorm.DB, token, version string) (*Record, error) {
	log.Tracef("getRecordVersion: %v %v", token, version)

	r := Record{
		Key: token + version,
	}
	err := db.Preload("Metadata").
		Preload("Files").
		Find(&r).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return nil, err
	}
	return &r, nil
}

// RecordVersion gets the specified version of a record from the database.
func (c *cockroachdb) RecordVersion(token, version string) (*cache.Record, error) {
	log.Tracef("RecordVersion: %v %v", token, version)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return nil, cache.ErrShutdown
	}

	r, err := c.recordVersion(c.recordsdb, token, version)
	if err != nil {
		return nil, err
	}

	cr := convertRecordToCache(*r)
	return &cr, nil
}

// Record gets the most recent version of a record from the database.
func (c *cockroachdb) Record(token string) (*cache.Record, error) {
	log.Tracef("Record: %v", token)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return nil, cache.ErrShutdown
	}

	var r Record
	err := c.recordsdb.
		Where("records.token = ?", token).
		Order("records.version desc").
		Limit(1).
		Preload("Metadata").
		Preload("Files").
		Find(&r).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return nil, err
	}

	cr := convertRecordToCache(r)
	return &cr, nil
}

// updateRecord updates a record in the database.  This includes updating the
// record as well as any metadata streams and files that are associated with
// the record. The existing record metadata streams and files are deleted from
// the database before the passed in metadata streams and files are added.
//
// This function must be called within a transaction.
func (c *cockroachdb) updateRecord(tx *gorm.DB, updated Record) error {
	log.Tracef("updateRecord: %v %v", updated.Token, updated.Version)

	// Ensure record exists. We need to do this because updates
	// will not return an error if you try to update a record that
	// does not exist.
	record, err := c.recordVersion(tx, updated.Token, updated.Version)
	if err != nil {
		return err
	}

	// Update record
	err = tx.Model(&record).
		Updates(map[string]interface{}{
			"status":    updated.Status,
			"timestamp": updated.Timestamp,
			"merkle":    updated.Merkle,
			"signature": updated.Signature,
		}).Error
	if err != nil {
		return fmt.Errorf("update record: %v", err)
	}

	// Delete existing metadata streams
	err = tx.Where("record_key = ?", record.Key).
		Delete(MetadataStream{}).
		Error
	if err != nil {
		return fmt.Errorf("delete metadata streams: %v", err)
	}

	// Add new metadata streams
	for _, ms := range updated.Metadata {
		err = tx.Create(&MetadataStream{
			RecordKey: record.Key,
			ID:        ms.ID,
			Payload:   ms.Payload,
		}).Error
		if err != nil {
			return fmt.Errorf("create metadata stream %v: %v", ms.ID, err)
		}
	}

	// Delete existing files
	err = tx.Where("record_key = ?", record.Key).
		Delete(File{}).
		Error
	if err != nil {
		return fmt.Errorf("delete files: %v", err)
	}

	// Add new files
	for _, f := range updated.Files {
		err = tx.Create(&File{
			RecordKey: record.Key,
			Name:      f.Name,
			MIME:      f.MIME,
			Digest:    f.Digest,
			Payload:   f.Payload,
		}).Error
		if err != nil {
			return fmt.Errorf("create file %v: %v", f.Name, err)
		}
	}

	return nil
}

// UpdateRecord updates a record in the database.  This includes updating the
// record as well as any metadata streams and files that are associated with
// the record.
func (c *cockroachdb) UpdateRecord(r cache.Record) error {
	log.Tracef("UpdateRecord: %v %v", r.CensorshipRecord.Token, r.Version)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return cache.ErrShutdown
	}

	// Run update within a transaction
	tx := c.recordsdb.Begin()
	err := c.updateRecord(tx, convertRecordFromCache(r))
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

// updateRecordStatus updates the status of a record in the database.  This
// includes updating the record as well as any metadata streams that are
// associated with the record.  The existing metadata streams are deleted from
// the database before the passed in metadata streams are added.
//
// This function must be called within a transaction.
func (c *cockroachdb) updateRecordStatus(tx *gorm.DB, token, version string, status int, timestamp int64, metadata []MetadataStream) error {
	log.Tracef("updateRecordStatus: %v %v", token, version)

	// Ensure record exists. We need to do this because updates
	// will not return an error if you try to update a record that
	// does not exist.
	record, err := c.recordVersion(tx, token, version)
	if err != nil {
		return err
	}

	// Update record
	err = tx.Model(&record).
		Updates(map[string]interface{}{
			"status":    status,
			"timestamp": timestamp,
		}).Error
	if err != nil {
		return fmt.Errorf("update record: %v", err)
	}

	// Delete existing metadata streams
	err = tx.Where("record_key = ?", record.Key).
		Delete(MetadataStream{}).
		Error
	if err != nil {
		return fmt.Errorf("delete metadata streams: %v", err)
	}

	// Add new metadata streams
	for _, ms := range metadata {
		err = tx.Create(&MetadataStream{
			RecordKey: record.Key,
			ID:        ms.ID,
			Payload:   ms.Payload,
		}).Error
		if err != nil {
			return fmt.Errorf("create metadata stream %v: %v", ms.ID, err)
		}
	}

	return nil
}

// UpdateRecordStatus updates the status of a record in the database.  This
// includes an update to the record as well as replacing the existing record
// metadata streams with the passed in metadata streams.
func (c *cockroachdb) UpdateRecordStatus(token, version string, status cache.RecordStatusT, timestamp int64, metadata []cache.MetadataStream) error {
	log.Tracef("UpdateRecordStatus: %v %v", token, status)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return cache.ErrShutdown
	}

	mdStreams := make([]MetadataStream, 0, len(metadata))
	for _, ms := range metadata {
		mdStreams = append(mdStreams, convertMDStreamFromCache(ms))
	}

	// Run update within a transaction
	tx := c.recordsdb.Begin()
	err := c.updateRecordStatus(tx, token, version, int(status),
		timestamp, mdStreams)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

// Inventory returns the latest version of all records from the database.
func (c *cockroachdb) Inventory() ([]cache.Record, error) {
	log.Tracef("Inventory")

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return nil, cache.ErrShutdown
	}

	// This query gets the latest version of each record
	query := `SELECT a.* FROM records a
		LEFT OUTER JOIN records b
			ON a.token = b.token AND a.version < b.version
		WHERE b.token IS NULL`

	rows, err := c.recordsdb.Raw(query).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]Record, 0, 1024) // PNOOMA
	for rows.Next() {
		var r Record
		err := c.recordsdb.ScanRows(rows, &r)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	// XXX this could be done in a more efficient way
	keys := make([]string, 0, len(records))
	for _, r := range records {
		keys = append(keys, r.Key)
	}
	err = c.recordsdb.
		Preload("Files").
		Preload("Metadata").
		Where(keys).
		Find(&records).
		Error
	if err != nil {
		return nil, err
	}

	cr := make([]cache.Record, 0, len(records))
	for _, r := range records {
		cr = append(cr, convertRecordToCache(r))
	}

	return cr, nil
}

// InventoryStats compiles summary statistics on the number of records in the
// database grouped by record status.  Only the latest version of each record
// is included in the statistics.
func (c *cockroachdb) InventoryStats() (*cache.InventoryStats, error) {
	log.Tracef("InventoryStats")

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return nil, cache.ErrShutdown
	}

	// This query gets the latest version of each record
	query := `SELECT a.* FROM records a
		LEFT OUTER JOIN records b
			ON a.token = b.token AND a.version < b.version
		WHERE b.token IS NULL`

	rows, err := c.recordsdb.Raw(query).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]Record, 0, 1024) // PNOOMA
	for rows.Next() {
		var r Record
		err := c.recordsdb.ScanRows(rows, &r)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	var is cache.InventoryStats
	for _, r := range records {
		switch cache.RecordStatusT(r.Status) {
		case cache.RecordStatusNotReviewed:
			is.NotReviewed++
		case cache.RecordStatusCensored:
			is.Censored++
		case cache.RecordStatusPublic:
			is.Public++
		case cache.RecordStatusUnreviewedChanges:
			is.UnreviewedChanges++
		case cache.RecordStatusArchived:
			is.Archived++
		default:
			is.Invalid++
		}
	}

	return &is, nil
}

func (c *cockroachdb) getPlugin(id string) (cache.PluginDriver, error) {
	c.Lock()
	defer c.Unlock()
	plugin, ok := c.plugins[id]
	if !ok {
		return nil, cache.ErrInvalidPlugin
	}
	return plugin, nil
}

// PluginExec is a pass through function for plugin commands.
func (c *cockroachdb) PluginExec(pc cache.PluginCommand) (*cache.PluginCommandReply, error) {
	log.Tracef("PluginExec: %v", pc.ID)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return nil, cache.ErrShutdown
	}

	plugin, err := c.getPlugin(pc.ID)
	if err != nil {
		return nil, err
	}

	payload, err := plugin.Exec(pc.Command, pc.CommandPayload,
		pc.ReplyPayload)
	if err != nil {
		return nil, err
	}

	return &cache.PluginCommandReply{
		ID:      pc.ID,
		Command: pc.Command,
		Payload: payload,
	}, nil
}

// PluginSetup sets up the database tables for the passed in plugin.
func (c *cockroachdb) PluginSetup(id string) error {
	log.Tracef("PluginSetup: %v", id)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return cache.ErrShutdown
	}

	plugin, err := c.getPlugin(id)
	if err != nil {
		return err
	}

	return plugin.Setup()
}

// RegisterPlugin registers and plugin with the cache and checks to make sure
// that the cache is using the correct plugin version.
func (c *cockroachdb) RegisterPlugin(p cache.Plugin) error {
	log.Tracef("RegisterPlugin: %v", p.ID)

	c.Lock()
	defer c.Unlock()

	if c.shutdown {
		return cache.ErrShutdown
	}

	_, ok := c.plugins[p.ID]
	if ok {
		return cache.ErrDuplicatePlugin
	}

	// Register the plugin
	var pd cache.PluginDriver
	switch p.ID {
	case decredplugin.ID:
		pd = newDecredPlugin(c.recordsdb, p)
		c.plugins[decredplugin.ID] = pd
	default:
		return cache.ErrInvalidPlugin
	}

	// Ensure we're using the correct plugin version
	return pd.CheckVersion()
}

// PluginBuilds builds the cache for the passed in plugin.
func (c *cockroachdb) PluginBuild(id, payload string) error {
	log.Tracef("PluginBuild: %v", id)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return cache.ErrShutdown
	}

	plugin, err := c.getPlugin(id)
	if err != nil {
		return err
	}

	log.Infof("Building plugin cache: %v", id)

	return plugin.Build(payload)
}

// createTables creates the database tables if they do not already exist.  A
// version record is inserted into the database during table creation.
//
// This function must be called within a transaction.
func (c *cockroachdb) createTables(tx *gorm.DB) error {
	log.Tracef("createTables")

	if !tx.HasTable(tableVersions) {
		err := tx.CreateTable(&Version{}).Error
		if err != nil {
			return err
		}
		// Add record version
		err = tx.Create(
			&Version{
				ID:        cacheID,
				Version:   cacheVersion,
				Timestamp: time.Now().Unix(),
			}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableRecords) {
		err := tx.CreateTable(&Record{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableMetadataStreams) {
		err := tx.CreateTable(&MetadataStream{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableFiles) {
		err := tx.CreateTable(&File{}).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// Setup creates the database tables for the records cache if they do not
// already exist. A version record is inserted into the database during table
// creation.
func (c *cockroachdb) Setup() error {
	log.Tracef("Setup tables")

	c.Lock()
	defer c.Unlock()

	if c.shutdown {
		return cache.ErrShutdown
	}

	tx := c.recordsdb.Begin()
	err := c.createTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// build the records cache using the passed in records.
//
// This funcion must be called within a transaction.
func (c *cockroachdb) build(tx *gorm.DB, records []Record) error {
	log.Tracef("build")

	err := c.createTables(tx)
	if err != nil {
		return err
	}

	for _, r := range records {
		err := tx.Create(&r).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// Build drops all existing tables from the records cache, recreates them, then
// builds the records cache using the passed in records.
func (c *cockroachdb) Build(records []cache.Record) error {
	log.Tracef("Build")

	c.Lock()
	defer c.Unlock()

	if c.shutdown {
		return cache.ErrShutdown
	}

	log.Infof("Building records cache")

	var r []Record
	for _, cr := range records {
		r = append(r, convertRecordFromCache(cr))
	}

	// Drop all current tables from the cache
	err := c.recordsdb.DropTableIfExists(tableVersions, tableRecords,
		tableMetadataStreams, tableFiles).Error
	if err != nil {
		return err
	}

	// Use a transaction to create new tables and to add all the
	// politeiad records to the cache
	tx := c.recordsdb.Begin()
	err = c.build(tx, r)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// Close shuts down the cache.  All interface functions MUST return with
// errShutdown if the backend is shutting down.
func (c *cockroachdb) Close() {
	log.Tracef("Close")

	c.Lock()
	defer c.Unlock()

	c.shutdown = true
	c.recordsdb.Close()
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
		plugins:   make(map[string]cache.PluginDriver),
	}

	// Disable gorm logging. This prevents duplicate errors from
	// being printed since we handle errors manually.
	c.recordsdb.LogMode(false)

	// Disable automatic table name pluralization. We set table
	// names manually.
	c.recordsdb.SingularTable(true)

	// Ensure we're using the correct cache version.
	var v Version
	if c.recordsdb.HasTable(tableVersions) {
		err = c.recordsdb.
			Where("id = ?", cacheID).
			Find(&v).
			Error
		if err != nil {
			return nil, err
		}
	}

	// Return an error if the version is incorrect, but also
	// return the database context so that the cache can be
	// rebuilt.
	if v.Version != cacheVersion {
		err = cache.ErrWrongVersion
	}

	log.Infof("Cache host: %v", h)

	return c, err
}
