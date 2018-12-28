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
	CacheVersion uint32 = 1

	tableVersion           = "version"
	tableRecords           = "records"
	tableCensorshipRecords = "censorship_records"
	tableMetadataStreams   = "metadata_streams"
	tableFiles             = "files"
)

// cockroachdb implements the cache interface
type cockroachdb struct {
	sync.RWMutex
	shutdown bool     // Backend is shutdown
	recorddb *gorm.DB // Database context
}

// New creates a new cockroachdb instance.
func New(host, rootCert, certDir string) (*cockroachdb, error) {
	log.Tracef("New: %v", host)

	// Connect to database
	u, err := url.Parse("postgresql://" + host)
	if err != nil {
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
		return nil, err
	}

	c := &cockroachdb{
		recorddb: db,
	}

	// Disable gorm logging. This prevents duplicate error messages
	// from being printed since we handle errors manually.
	c.recorddb.LogMode(false)

	log.Infof("Cache host: %v", host)

	return c, nil
}

// This function must be called within a transaction.
func (c *cockroachdb) createTables(db *gorm.DB) error {
	if !db.HasTable(tableVersion) {
		err := db.Table(tableVersion).
			CreateTable(&Version{}).Error
		if err != nil {
			return err
		}
		// Set cache version
		err = db.Table(tableVersion).Create(
			&Version{
				Version: CacheVersion,
				Time:    time.Now().Unix(),
			}).Error
		if err != nil {
			return err
		}
	}
	if !db.HasTable(tableRecords) {
		err := db.Table(tableRecords).
			CreateTable(&Record{}).Error
		if err != nil {
			return err
		}
	}
	if !db.HasTable(tableCensorshipRecords) {
		err := db.Table(tableCensorshipRecords).
			CreateTable(&CensorshipRecord{}).Error
		if err != nil {
			return err
		}
	}
	if !db.HasTable(tableMetadataStreams) {
		err := db.Table(tableMetadataStreams).
			CreateTable(&MetadataStream{}).Error
		if err != nil {
			return err
		}
	}
	if !db.HasTable(tableFiles) {
		err := db.Table(tableFiles).
			CreateTable(&File{}).Error
		if err != nil {
			return err
		}
	}
	return nil
}

// CrateTables creates the database tables if they do not already exist and
// sets the cache version.
func (c *cockroachdb) CreateTables() error {
	log.Tracef("CreateTables")

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown == true {
		return cache.ErrShutdown
	}

	tx := c.recorddb.Begin()
	err := c.createTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

func (c *cockroachdb) CreatePluginTables() error {
	log.Tracef("CreatePluginTables")

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown == true {
		return cache.ErrShutdown
	}

	tx := c.recorddb.Begin()
	err := createDecredTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

func (c *cockroachdb) RecordNew(cr cache.Record) error {
	log.Tracef("RecordNew: %v", cr.CensorshipRecord.Token)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown == true {
		return cache.ErrShutdown
	}

	r := convertRecordFromCache(cr)
	// TODO: this should be set in convertRecordFromCache
	r.Key = r.CensorshipRecord.Token + r.Version
	return c.recorddb.Create(&r).Error
}

func (c *cockroachdb) recordGet(token, version string) (*Record, error) {
	log.Tracef("recordGet: %v version %v", token, version)

	r := Record{
		Key: token + version,
	}
	err := c.recorddb.
		Preload("CensorshipRecord").
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

func (c *cockroachdb) RecordGet(token, version string) (*cache.Record, error) {
	log.Tracef("RecordGet: %v version %v", token, version)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown == true {
		return nil, cache.ErrShutdown
	}

	r, err := c.recordGet(token, version)
	if err != nil {
		return nil, err
	}

	cr := convertRecordToCache(*r)
	return &cr, nil
}

func (c *cockroachdb) RecordGetLatest(token string) (*cache.Record, error) {
	log.Tracef("RecordGetLatest: %v", token)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown == true {
		return nil, cache.ErrShutdown
	}

	var r Record
	err := c.recorddb.Joins("JOIN censorship_records "+
		"ON censorship_records.key = records.censorship_record_key ").
		Where("censorship_records.token = ?", token).
		Order("records.version desc").
		Limit(1).
		Preload("CensorshipRecord").
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

// This function must be called within a transaction.
func (c *cockroachdb) recordUpdate(db *gorm.DB, updated Record) error {
	log.Tracef("recordUpdate: %v version %v",
		updated.CensorshipRecord.Token, updated.Version)

	// Ensure record exists. We need to do this because updates will
	// not return an error if you try to update a record that does
	// not exist.
	record, err := c.recordGet(updated.CensorshipRecord.Token, updated.Version)
	if err != nil {
		return err
	}

	// Update record
	err = db.Model(&record).
		Updates(map[string]interface{}{
			"status":    updated.Status,
			"timestamp": updated.Timestamp,
		}).Error
	if err != nil {
		return fmt.Errorf("update record: %v", err)
	}

	// Update censorship record
	err = db.Model(&record.CensorshipRecord).
		Updates(map[string]interface{}{
			"token":     updated.CensorshipRecord.Token,
			"merkle":    updated.CensorshipRecord.Merkle,
			"signature": updated.CensorshipRecord.Signature,
		}).Error
	if err != nil {
		return fmt.Errorf("update censorship record: %v", err)
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
			return fmt.Errorf("update file %v: %v", f.Name, err)
		}
	}

	return nil
}

func (c *cockroachdb) RecordUpdate(r cache.Record) error {
	log.Tracef("RecordUpdate: %v version %v",
		r.CensorshipRecord.Token, r.Version)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown == true {
		return cache.ErrShutdown
	}

	// Run update within a transaction
	tx := c.recorddb.Begin()
	err := c.recordUpdate(tx, convertRecordFromCache(r))
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

// This function must be called within a transaction.
func (c *cockroachdb) recordUpdateStatus(db *gorm.DB, token, version string, status int, timestamp int64, metadata []MetadataStream) error {
	log.Tracef("recordUpdateStatus: %v version %v", token, version)

	// Ensure record exists.  We need to do this because updates
	// will not return an error if you try to update a record that
	// does not exist.
	record, err := c.recordGet(token, version)
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
			return fmt.Errorf("create metadata stream: %v", err)
		}
	}

	return nil
}

func (c *cockroachdb) RecordUpdateStatus(token, version string, status cache.RecordStatusT, timestamp int64, metadata []cache.MetadataStream) error {
	log.Tracef("RecordUpdateStatus: %v status %v", token, status)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown == true {
		return cache.ErrShutdown
	}

	// Convert metadata
	mdStreams := make([]MetadataStream, 0, len(metadata))
	for _, ms := range metadata {
		mdStreams = append(mdStreams, convertMDStreamFromCache(ms))
	}

	// Run update within a transaction
	tx := c.recorddb.Begin()
	err := c.recordUpdateStatus(tx, token, version, int(status),
		timestamp, mdStreams)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

// Plugin is a pass through function for plugin commands.  Plugin commands that
// write data to the cache require both the request payload and the response
// payload.  Plugin commands that fetch data from the cache only require the
// request payload.  All plugin commands return the response payload and any
// errors that occured.
func (c *cockroachdb) Plugin(command, reqPayload, resPayload string) (string, error) {
	log.Tracef("Plugin: %v", command)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown == true {
		return "", cache.ErrShutdown
	}

	switch command {
	case decredplugin.CmdNewComment:
		return c.pluginNewComment(reqPayload, resPayload)
	case decredplugin.CmdGetComment:
		return c.pluginGetComment(reqPayload)
	case decredplugin.CmdGetComments:
		return c.pluginGetComments(reqPayload)
	case decredplugin.CmdLikeComment:
		return c.pluginLikeComment(reqPayload, resPayload)
	case decredplugin.CmdCensorComment:
		return c.pluginCensorComment(reqPayload, resPayload)
	}
	return "", cache.ErrInvalidPluginCmd
}

// Close shuts down the cache.  All interface functions MUST return with
// errShutdown if the backend is shutting down.
func (c *cockroachdb) Close() {
	log.Tracef("Close")

	c.Lock()
	defer c.Unlock()

	c.shutdown = true
	c.recorddb.Close()
}
