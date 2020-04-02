// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/thi4go/politeia/decredplugin"
	"github.com/thi4go/politeia/politeiad/cache"
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

	// Plugin hooks
	pluginHookPostNewRecord            = "postnewrecord"
	pluginHookPostUpdateRecord         = "postupdaterecord"
	pluginHookPostUpdateRecordMetadata = "postupdaterecordmetadata"

	// Database users
	UserPoliteiad   = "politeiad"   // politeiad user (read/write access)
	UserPoliteiawww = "politeiawww" // politeiawww user (read access)
)

// cockroachdb implements the cache interface.
type cockroachdb struct {
	sync.RWMutex
	shutdown  bool                          // Backend is shutdown
	recordsdb *gorm.DB                      // Database context
	plugins   map[string]cache.PluginDriver // [pluginID]PluginDriver
}

func (c *cockroachdb) newRecord(tx *gorm.DB, r Record) error {
	// Insert record
	err := tx.Create(&r).Error
	if err != nil {
		return err
	}

	// Call plugin hooks
	if c.pluginIsRegistered(decredplugin.ID) {
		plugin, err := c.getPlugin(decredplugin.ID)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(r)
		if err != nil {
			return err
		}
		err = plugin.Hook(tx, pluginHookPostNewRecord, string(payload))
		if err != nil {
			return err
		}
	}

	return nil
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

	v, err := strconv.ParseUint(cr.Version, 10, 64)
	if err != nil {
		return fmt.Errorf("parse version '%v' failed: %v",
			cr.Version, err)
	}
	r := convertRecordFromCache(cr, v)

	tx := c.recordsdb.Begin()
	err = c.newRecord(tx, r)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
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

// record gets the most recent version of a record from the database.  This
// function has a database parameter so that it can be called inside of a
// transaction when required.
func record(db *gorm.DB, token string) (*Record, error) {
	var r Record
	err := db.
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
	return &r, nil
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

	r, err := record(c.recordsdb, token)
	if err != nil {
		return nil, err
	}

	cr := convertRecordToCache(*r)
	return &cr, nil
}

// updateMetadataStreams updates a record's metadata streams by deleting the
// existing metadata streams then adding the passed in metadata streams to the
// database.
//
// This function must be called using a transaction.
func updateMetadataStreams(tx *gorm.DB, key string, ms []MetadataStream) error {
	// Delete existing metadata streams
	err := tx.Where("record_key = ?", key).
		Delete(MetadataStream{}).
		Error
	if err != nil {
		return fmt.Errorf("delete MD streams: %v", err)
	}

	// Add new metadata streams
	for _, v := range ms {
		err = tx.Create(&MetadataStream{
			RecordKey: key,
			ID:        v.ID,
			Payload:   v.Payload,
		}).Error
		if err != nil {
			return fmt.Errorf("create MD stream %v: %v",
				v.ID, err)
		}
	}

	return nil
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
	record, err := c.recordVersion(tx, updated.Token,
		strconv.FormatUint(updated.Version, 10))
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

	// Update metadata
	err = updateMetadataStreams(tx, record.Key, updated.Metadata)
	if err != nil {
		return err
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

	// Call plugin hooks
	if c.pluginIsRegistered(decredplugin.ID) {
		plugin, err := c.getPlugin(decredplugin.ID)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(updated)
		if err != nil {
			return err
		}
		err = plugin.Hook(tx, pluginHookPostUpdateRecord, string(payload))
		if err != nil {
			return err
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

	v, err := strconv.ParseUint(r.Version, 10, 64)
	if err != nil {
		return fmt.Errorf("parse version '%v' failed: %v",
			r.Version, err)
	}

	// Run update within a transaction
	tx := c.recordsdb.Begin()
	err = c.updateRecord(tx, convertRecordFromCache(r, v))
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

	// Update metadata
	return updateMetadataStreams(tx, record.Key, metadata)
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

// updateRecordMetadata updates the metadata streams of the given record. It
// does this by first deleting the existing metadata streams then adding the
// passed in metadata streams to the database.
//
// This function must be called using a transaction.
func (c *cockroachdb) updateRecordMetadata(tx *gorm.DB, token string, ms []MetadataStream) error {
	// Ensure record exists. This is required because updates
	// will not return an error if the record does not exist.
	r, err := record(tx, token)
	if err != nil {
		return err
	}

	// Update metadata
	err = updateMetadataStreams(tx, r.Key, ms)
	if err != nil {
		return err
	}

	// Call plugin hooks
	if c.pluginIsRegistered(decredplugin.ID) {
		plugin, err := c.getPlugin(decredplugin.ID)
		if err != nil {
			return err
		}
		err = plugin.Hook(tx, pluginHookPostUpdateRecordMetadata, "")
		if err != nil {
			return err
		}
	}

	return nil
}

// UpdateRecordMetadata updates the metadata streams of the given record. It
// does this by first deleting the existing metadata streams then adding the
// passed in metadata streams to the database.
func (c *cockroachdb) UpdateRecordMetadata(token string, ms []cache.MetadataStream) error {
	log.Tracef("UpdateRecordMetadata: %v", token)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return cache.ErrShutdown
	}

	m := convertMDStreamsFromCache(ms)

	// Run update in a transaction
	tx := c.recordsdb.Begin()
	err := c.updateRecordMetadata(tx, token, m)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

// getRecords returns the records for the provided censorship tokens. If a
// record is not found for a provided token, the returned records slice will
// not include an entry for it.
func (c *cockroachdb) getRecords(tokens []string, fetchFiles bool) ([]Record, error) {
	// Lookup the latest version of each record specified by
	// the provided tokens.
	query := `SELECT a.*
            FROM records a
            LEFT OUTER JOIN records b
              ON a.token = b.token
              AND a.version < b.version
              WHERE b.token IS NULL
              AND a.token IN (?)`
	rows, err := c.recordsdb.Raw(query, tokens).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]Record, 0, len(tokens))
	for rows.Next() {
		var r Record
		err := c.recordsdb.ScanRows(rows, &r)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	// Compile a list of record primary keys
	keys := make([]string, 0, len(records))
	for _, v := range records {
		keys = append(keys, v.Key)
	}

	if fetchFiles {
		// Lookup files and metadata streams for each of the
		// previously queried records.
		err = c.recordsdb.
			Preload("Metadata").
			Preload("Files").
			Where(keys).
			Find(&records).
			Error
	} else {
		// Lookup just the metadata streams for each of the
		// previously queried records.
		err = c.recordsdb.
			Preload("Metadata").
			Where(keys).
			Find(&records).
			Error
	}

	return records, err
}

// Records returns a [token]cache.Record map for the provided censorship
// tokens. If a record is not found, the map will not include an entry for the
// corresponding censorship token. It is the responsibility of the caller to
// ensure that results are returned for all of the provided censorship tokens.
func (c *cockroachdb) Records(tokens []string, fetchFiles bool) (map[string]cache.Record, error) {
	log.Tracef("Records: %v", tokens)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return nil, cache.ErrShutdown
	}

	records, err := c.getRecords(tokens, fetchFiles)
	if err != nil {
		return nil, err
	}

	// Compile records map
	cr := make(map[string]cache.Record, len(records)) // [token]cache.Record
	for _, r := range records {
		cr[r.Token] = convertRecordToCache(r)
	}

	return cr, nil
}

// inventory returns the latest version of every record in the cache.
func (c *cockroachdb) inventory() ([]Record, error) {
	// Lookup the latest version of all records
	query := `SELECT a.*
            FROM records a
            LEFT OUTER JOIN records b
              ON a.token = b.token
              AND a.version < b.version
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
	if err = rows.Err(); err != nil {
		return nil, err
	}

	// Compile a list of record primary keys
	keys := make([]string, 0, len(records))
	for _, v := range records {
		keys = append(keys, v.Key)
	}

	// Lookup the files and metadata streams for each of the
	// previously queried records.
	err = c.recordsdb.
		Preload("Metadata").
		Preload("Files").
		Where(keys).
		Find(&records).
		Error
	if err != nil {
		return nil, err
	}

	return records, nil
}

// Inventory returns the latest version of all records in the cache.
func (c *cockroachdb) Inventory() ([]cache.Record, error) {
	log.Tracef("Inventory")

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return nil, cache.ErrShutdown
	}

	inv, err := c.inventory()
	if err != nil {
		return nil, err
	}

	cr := make([]cache.Record, 0, len(inv))
	for _, v := range inv {
		cr = append(cr, convertRecordToCache(v))
	}

	return cr, nil
}

func (c *cockroachdb) pluginIsRegistered(pluginID string) bool {
	c.RLock()
	defer c.RUnlock()

	_, ok := c.plugins[pluginID]
	return ok
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
// version record for the cache is inserted into the database during this
// process if one does not already exist.
//
// This function must be called within a transaction.
func (c *cockroachdb) createTables(tx *gorm.DB) error {
	log.Tracef("createTables")

	if !tx.HasTable(tableVersions) {
		err := tx.CreateTable(&Version{}).Error
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

	var v Version
	err := tx.Where("id = ?", cacheID).
		Find(&v).
		Error
	if err == gorm.ErrRecordNotFound {
		err = tx.Create(
			&Version{
				ID:        cacheID,
				Version:   cacheVersion,
				Timestamp: time.Now().Unix(),
			}).Error
	}

	return err
}

func (c *cockroachdb) dropTables(tx *gorm.DB) error {
	// Drop record tables
	err := tx.DropTableIfExists(tableRecords,
		tableMetadataStreams, tableFiles).Error
	if err != nil {
		return err
	}

	// Remove cache version record
	return tx.Delete(&Version{
		ID: cacheID,
	}).Error
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
// This function cannot be called using a transaction because it could
// potentially exceed cockroachdb's transaction size limit.
func (c *cockroachdb) build(records []Record) error {
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
	err = c.createTables(tx)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("create tables: %v", err)
	}
	err = tx.Commit().Error
	if err != nil {
		return err
	}

	// Populate record tables
	for _, r := range records {
		err := c.recordsdb.Create(&r).Error
		if err != nil {
			log.Debugf("create record failed on '%v'", r)
			return fmt.Errorf("create record: %v", err)
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

	r := make([]Record, 0, len(records))
	for _, cr := range records {
		v, err := strconv.ParseUint(cr.Version, 10, 64)
		if err != nil {
			return fmt.Errorf("parse version '%v' failed %v: %v",
				cr.Version, cr.CensorshipRecord.Token, err)
		}
		r = append(r, convertRecordFromCache(cr, v))
	}

	// Build the records cache. This is not run using a
	// transaction because it could potentially exceed
	// cockroachdb's transaction size limit.
	err := c.build(r)
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

	log.Infof("Cache host: %v", h)

	// Return an error if the version record is not found or
	// if there is a version mismatch, but also return the
	// cache context so that the cache can be built/rebuilt.
	if !c.recordsdb.HasTable(tableVersions) {
		log.Debugf("table '%v' does not exist", tableVersions)
		return c, cache.ErrNoVersionRecord
	}

	var v Version
	err = c.recordsdb.
		Where("id = ?", cacheID).
		Find(&v).
		Error
	if err == gorm.ErrRecordNotFound {
		log.Debugf("version record not found for ID '%v'", cacheID)
		err = cache.ErrNoVersionRecord
	} else if v.Version != cacheVersion {
		log.Debugf("version mismatch for ID '%v': got %v, want %v",
			cacheID, v.Version, cacheVersion)
		err = cache.ErrWrongVersion
	}

	return c, err
}
