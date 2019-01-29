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
	recordVersion uint32 = 1

	// The database is named by prefixing the dbPrefix onto the network
	// name (ex. records_mainnet)
	dbPrefix = "records_"

	// Database table names
	tableVersion         = "version"
	tableRecords         = "records"
	tableMetadataStreams = "metadata_streams"
	tableFiles           = "files"

	// Database users
	UserPoliteiad   = "politeiad"   // politeiad user (read/write access)
	UserPoliteiawww = "politeiawww" // politeiawww user (read access)
)

// cockroachdb implements the cache interface
type cockroachdb struct {
	sync.RWMutex
	shutdown  bool                          // Backend is shutdown
	recordsdb *gorm.DB                      // Database context
	plugins   map[string]cache.PluginDriver // [pluginID]PluginDriver
}

// NewRecord creates a new entry in the database for the given record.
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

// getRecordVersion gets the specified version of a record from the database.
func getRecordVersion(db *gorm.DB, token, version string) (*Record, error) {
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

	r, err := getRecordVersion(c.recordsdb, token, version)
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
// the database before the given metadata streams and files are added.
//
// This function must be called within a transaction.
func updateRecord(db *gorm.DB, updated Record) error {
	log.Tracef("updateRecord: %v %v", updated.Token, updated.Version)

	// Ensure record exists. We need to do this because updates
	// will not return an error if you try to update a record that
	// does not exist.
	record, err := getRecordVersion(db, updated.Token, updated.Version)
	if err != nil {
		return err
	}

	// Update record
	err = db.Model(&record).
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
	err = db.Where("record_key = ?", record.Key).
		Delete(MetadataStream{}).
		Error
	if err != nil {
		return fmt.Errorf("delete metadata streams: %v", err)
	}

	// Add new metadata streams
	for _, ms := range updated.Metadata {
		err = db.Create(&MetadataStream{
			RecordKey: record.Key,
			ID:        ms.ID,
			Payload:   ms.Payload,
		}).Error
		if err != nil {
			return fmt.Errorf("create metadata stream %v: %v", ms.ID, err)
		}
	}

	// Delete existing files
	err = db.Where("record_key = ?", record.Key).
		Delete(File{}).
		Error
	if err != nil {
		return fmt.Errorf("delete files: %v", err)
	}

	// Add new files
	for _, f := range updated.Files {
		err = db.Create(&File{
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
	err := updateRecord(tx, convertRecordFromCache(r))
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
func updateRecordStatus(db *gorm.DB, token, version string, status int, timestamp int64, metadata []MetadataStream) error {
	log.Tracef("updateRecordStatus: %v %v", token, version)

	// Ensure record exists. We need to do this because updates
	// will not return an error if you try to update a record that
	// does not exist.
	record, err := getRecordVersion(db, token, version)
	if err != nil {
		return err
	}

	// Update record
	err = db.Model(&record).
		Updates(map[string]interface{}{
			"status":    status,
			"timestamp": timestamp,
		}).Error
	if err != nil {
		return fmt.Errorf("update record: %v", err)
	}

	// Delete existing metadata streams
	err = db.Where("record_key = ?", record.Key).
		Delete(MetadataStream{}).
		Error
	if err != nil {
		return fmt.Errorf("delete metadata streams: %v", err)
	}

	// Add new metadata streams
	for _, ms := range metadata {
		err = db.Create(&MetadataStream{
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
	err := updateRecordStatus(tx, token, version, int(status),
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
	defer rows.Close()
	if err != nil {
		return nil, err
	}

	records := make([]Record, 0, 1024) // PNOOMA
	for rows.Next() {
		var r Record
		c.recordsdb.ScanRows(rows, &r)
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
	defer rows.Close()
	if err != nil {
		return nil, err
	}

	records := make([]Record, 0, 1024) // PNOOMA
	for rows.Next() {
		var r Record
		c.recordsdb.ScanRows(rows, &r)
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

	is.Total = is.NotReviewed + is.Censored + is.Public +
		is.UnreviewedChanges + is.Archived + is.Invalid

	return &is, nil
}

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

	switch p.ID {
	case decredplugin.ID:
		c.plugins[decredplugin.ID] = newDecredPlugin(c.recordsdb, p)
	default:
		return cache.ErrInvalidPlugin
	}

	return nil
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

	return plugin.Build(payload)
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

// createTables creates the database tables if they do not already exist and
// sets the cache version.
//
// This function must be called within a transaction.
func createTables(db *gorm.DB) error {
	log.Tracef("createTables")

	if !db.HasTable(tableVersion) {
		err := db.CreateTable(&Version{}).Error
		if err != nil {
			return err
		}
		// Set cache version
		err = db.Create(
			&Version{
				Version:   recordVersion,
				Timestamp: time.Now().Unix(),
			}).Error
		if err != nil {
			return err
		}
	}
	if !db.HasTable(tableRecords) {
		err := db.CreateTable(&Record{}).Error
		if err != nil {
			return err
		}
	}
	if !db.HasTable(tableMetadataStreams) {
		err := db.CreateTable(&MetadataStream{}).Error
		if err != nil {
			return err
		}
	}
	if !db.HasTable(tableFiles) {
		err := db.CreateTable(&File{}).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// build creates the database tables if they don't already exist then adds the
// given records to the database.
//
// This funcion must be called within a transaction.
func build(db *gorm.DB, records []Record) error {
	log.Tracef("build")

	err := createTables(db)
	if err != nil {
		return err
	}

	for _, r := range records {
		err := db.Create(&r).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// Build drops all existing tables from the database, recreates them, then adds
// all of the given records to the new tables.
func (c *cockroachdb) Build(records []cache.Record) error {
	log.Tracef("Build")

	c.Lock()
	defer c.Unlock()

	if c.shutdown {
		return cache.ErrShutdown
	}

	log.Infof("Building cache")

	var r []Record
	for _, cr := range records {
		r = append(r, convertRecordFromCache(cr))
	}

	// Drop all current tables from the cache
	err := c.recordsdb.DropTableIfExists(tableVersion, tableRecords,
		tableMetadataStreams, tableFiles).Error
	if err != nil {
		return err
	}

	// Use a transaction to create new tables and to add all the
	// politeiad records to the cache
	tx := c.recordsdb.Begin()
	err = build(tx, r)
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

// New returns a new cockroachdb context that contains a connection to the
// specified database that was made using the passed in user and certificates.
func New(user, host, net, rootCert, certDir string) (*cockroachdb, error) {
	log.Tracef("New: %v %v %v %v %v", user, host, net, rootCert, certDir)

	// Connect to database
	h := "postgresql://" + user + "@" + host + "/" + dbPrefix + net
	u, err := url.Parse(h)
	if err != nil {
		log.Debugf("New: could not parse url %v", h)
		return nil, err
	}

	v := url.Values{}
	v.Set("ssl", "true")
	v.Set("sslmode", "require")
	v.Set("sslrootcert", filepath.Clean(rootCert))
	v.Set("sslkey", filepath.Join(certDir, "client."+u.User.String()+".key"))
	v.Set("sslcert", filepath.Join(certDir, "client."+u.User.String()+".crt"))

	addr := u.String() + "?" + v.Encode()
	db, err := gorm.Open("postgres", addr)
	if err != nil {
		log.Debugf("New: could not connect to %v", addr)
		return nil, err
	}

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

	// Check version
	var vr Version
	err = c.recordsdb.First(&vr).Error
	if err != nil {
		return nil, err
	} else if vr.Version != recordVersion {
		err = cache.ErrWrongVersion
	}

	log.Infof("Cache host: %v", h)

	return c, err
}

// Setup uses the CockroachDB root user to create a database, politeiad user,
// and politeiawww user if they do not already exist. User permissions are then
// set for the database and the database tables are created if they do not
// already exist. A Version record is inserted into the database during table
// creation.
func Setup(host, net, rootCert, certDir string) error {
	log.Tracef("Setup: %v %v %v %v", host, net, rootCert, certDir)

	// Connect to CockroachDB as root user. CockroachDB connects
	// to defaultdb when a database is not specified.
	h := "postgresql://root@" + host
	u, err := url.Parse(h)
	if err != nil {
		log.Debugf("Setup: could not parse url %v", h)
		return err
	}

	v := url.Values{}
	v.Set("ssl", "true")
	v.Set("sslmode", "require")
	v.Set("sslrootcert", filepath.Clean(rootCert))
	v.Set("sslkey", filepath.Join(certDir, "client."+u.User.String()+".key"))
	v.Set("sslcert", filepath.Join(certDir, "client."+u.User.String()+".crt"))

	addr := u.String() + "?" + v.Encode()
	db, err := gorm.Open("postgres", addr)
	defer db.Close()
	if err != nil {
		log.Debugf("Setup: could not connect to %v", addr)
		return err
	}

	// Setup records database and users
	dbName := dbPrefix + net
	q := "CREATE DATABASE IF NOT EXISTS " + dbName
	err = db.Exec(q).Error
	if err != nil {
		return err
	}
	q = "CREATE USER IF NOT EXISTS " + UserPoliteiad
	err = db.Exec(q).Error
	if err != nil {
		return err
	}
	q = "GRANT ALL ON DATABASE " + dbName + " TO " + UserPoliteiad
	err = db.Exec(q).Error
	if err != nil {
		return err
	}
	q = "CREATE USER IF NOT EXISTS " + UserPoliteiawww
	err = db.Exec(q).Error
	if err != nil {
		return err
	}
	q = "GRANT SELECT ON DATABASE " + dbName + " TO " + UserPoliteiawww
	err = db.Exec(q).Error
	if err != nil {
		return err
	}

	// Connect to records database with root user
	h = "postgresql://root@" + host + "/" + dbName
	u, err = url.Parse(h)
	if err != nil {
		log.Debugf("Setup: could not parse url %v", h)
		return err
	}
	addr = u.String() + "?" + v.Encode()
	recordsDB, err := gorm.Open("postgres", addr)
	defer recordsDB.Close()
	if err != nil {
		log.Debugf("Setup: could not connect to %v", addr)
		return err
	}

	// Setup database tables
	tx := recordsDB.Begin()
	err = createTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}
