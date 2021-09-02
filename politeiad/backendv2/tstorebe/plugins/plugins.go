// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/inv"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
)

// HookT represents a plugin hook.
type HookT int

const (
	// HookInvalid is an invalid plugin hook.
	HookInvalid HookT = 0

	// HookRecordNewPre is called before a new record is saved to disk.
	HookRecordNewPre HookT = 1

	// HookRecordNewPost is called after a new record is saved to disk.
	HookRecordNewPost HookT = 2

	// HookRecordEditPre is called before a record edit is saved to
	// disk.
	HookRecordEditPre HookT = 3

	// HookRecordEditPost is called after a record edit is saved to
	// disk.
	HookRecordEditPost HookT = 4

	// HookRecordEditMetadataPre is called before a record metadata
	// edit is saved to disk.
	HookRecordEditMetadataPre HookT = 5

	// HookRecordEditMetadataPost is called after a record metadata
	// edit is saved to disk.
	HookRecordEditMetadataPost HookT = 6

	// HookRecordSetStatusPre is called before a record status change
	// is saved to disk.
	HookRecordSetStatusPre HookT = 7

	// HookRecordSetStatusPost is called after a record status change
	// is saved to disk.
	HookRecordSetStatusPost HookT = 8

	// HookPluginWritePre is called before a write plugin command is
	// executed.
	HookPluginWritePre HookT = 9

	// HookPluginWritePost is called after a write plugin command is
	// executed.
	HookPluginWritePost HookT = 10

	// HookLast is used by unit tests to verify that all hooks have
	// an entry in the Hooks map. This hook will never be used.
	HookLast HookT = 11
)

var (
	// Hooks contains human readable descriptions for the plugin hooks.
	Hooks = map[HookT]string{
		HookInvalid:                "invalid hook",
		HookRecordNewPre:           "record new pre",
		HookRecordNewPost:          "record new post",
		HookRecordEditPre:          "record edit pre",
		HookRecordEditPost:         "record edit post",
		HookRecordEditMetadataPre:  "record edit metadata pre",
		HookRecordEditMetadataPost: "record edit metadata post",
		HookRecordSetStatusPre:     "record set status pre",
		HookRecordSetStatusPost:    "record set status post",
		HookPluginWritePre:         "plugin write pre",
		HookPluginWritePost:        "plugin write post",
	}
)

// RecordNew is the payload for the RecordNew hooks.
type RecordNew struct {
	Metadata []backend.MetadataStream `json:"metadata"`
	Files    []backend.File           `json:"files"`

	// RecordMetadata will only be populated on the post hook.
	RecordMetadata *backend.RecordMetadata `json:"recordmetadata,omitempty"`
}

// RecordEdit is the payload for the RecordEdit hooks.
type RecordEdit struct {
	// Record pre update
	Record backend.Record `json:"record"`

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	Metadata       []backend.MetadataStream `json:"metadata"`
	Files          []backend.File           `json:"files"`
}

// RecordEditMetadata is the payload for the RecordEditMetadata hooks.
type RecordEditMetadata struct {
	// Record pre update
	Record backend.Record `json:"record"`

	// Updated fields
	Metadata []backend.MetadataStream `json:"metadata"`
}

// RecordSetStatus is the payload for the RecordSetStatus hooks.
type RecordSetStatus struct {
	// Record pre update
	Record backend.Record `json:"record"`

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	Metadata       []backend.MetadataStream `json:"metadata"`
}

// PluginWrite is the payload for the PluginWrite hooks.
type PluginWrite struct {
	Token    []byte `json:"token"`
	PluginID string `json:"pluginid"`
	Cmd      string `json:"cmd"`
	Payload  string `json:"payload"`

	// Reply contains the plugin command reply payload and will only
	// be populated on the post hook.
	Reply string `json:"reply,omitempty"`
}

// PluginClient provides an API for a tstore instance to use when interacting
// with a plugin. All tstore plugins must implement the PluginClient interface.
type PluginClient interface {
	// Setup performs any required plugin setup.
	Setup() error

	// Write executes a write plugin command. All operations are
	// executed atomically by tstore when using this method. The
	// plugin does not need to worry about concurrency issues.
	Write(t TstoreClient, token []byte, cmd, payload string) (string, error)

	// Read executes a read-only plugin command. Read operations are
	// not not atomic.
	Read(t TstoreClient, token []byte, cmd, payload string) (string, error)

	// Hook executes a plugin hook. All operations are executed
	// atomically by tstore when using this method. The plugin
	// does not need to worry about concurrency issues.
	Hook(t TstoreClient, h HookT, payload string) error

	// Fsck performs a plugin file system check.
	Fsck() error

	// Settings returns the plugin settings.
	Settings() []backend.PluginSetting
}

// TODO remove the token argument. It will use the token that the command is
// being executed on.  Executing commands on other records requires the use
// of the Backend interace.
//
// TODO add in check that all write data descriptors are prefixed with the
// plugin id
//
// TstoreClient provides a concurrency safe API for plugins to interact with a
// tstore instance. Plugins are allowed to save, delete, and retrieve plugin
// data to/from the tstore instance.
//
// Operations will be atomic if the client is initialized by a plugin write
// command. Operations WILL NOT be atomic if the client is initialized by a
// plugin read command. The client will not allow write methods to be executed
// if it was initialized by a plugin read command.
//
// All data saved using this client will be timestamped onto the Decred
// blockchain and will have timestamp data available for retrieval.
type TstoreClient interface {
	// BlobSave saves a BlobEntry to the tstore instance. The BlobEntry
	// will be encrypted prior to being written to disk if the record
	// is unvetted. The digest of the data, i.e. BlobEntry.Digest, can
	// be thought of as the blob ID that can be used to get/del the
	// blob from tstore.
	BlobSave(token []byte, be store.BlobEntry) error

	// TODO Add BlobSaveUnsafe()

	// BlobsDel deletes the blobs that correspond to the provided
	// digests.
	BlobsDel(token []byte, digests [][]byte) error

	// Blobs returns the blobs that correspond to the provided digests.
	// If a blob does not exist it will not be included in the returned
	// map. If a record is vetted, only vetted blobs will be returned.
	Blobs(token []byte, digests [][]byte) (map[string]store.BlobEntry, error)

	// BlobsByDataDesc returns all blobs that match the provided data
	// descriptor. The blobs will be ordered from oldest to newest. If
	// a record is vetted then only vetted blobs will be returned.
	BlobsByDataDesc(token []byte, dataDesc []string) ([]store.BlobEntry, error)

	// DigestsByDataDesc returns the digests of all blobs that match
	// the provided data descriptor. The digests will be ordered from
	// oldest to newest. If a record is vetted, only vetted blobs will
	// be returned.
	DigestsByDataDesc(token []byte, dataDesc []string) ([][]byte, error)

	// Timestamp returns the timestamp for the blob that correpsonds
	// to the digest. If a record is vetted, only vetted timestamps
	// will be returned.
	Timestamp(token []byte, digest []byte) (*backend.Timestamp, error)

	// Record returns a version of a record.
	Record(token []byte, version uint32) (*backend.Record, error)

	// RecordLatest returns the most recent version of a record.
	RecordLatest(token []byte) (*backend.Record, error)

	// RecordPartial returns a partial record. This method gives the
	// caller fine grained control over what version and what files are
	// returned. The only required field is the token. All other fields
	// are optional.
	//
	// Version is used to request a specific version of a record. If no
	// version is provided then the most recent version of the record
	// will be returned.
	//
	// Filenames can be used to request specific files. If filenames is
	// not empty then the specified files will be the only files that
	// are returned.
	//
	// OmitAllFiles can be used to retrieve a record without any of the
	// record files. This supersedes the filenames argument.
	RecordPartial(token []byte, version uint32, filenames []string,
		omitAllFiles bool) (*backend.Record, error)

	// RecordState returns the record state.
	RecordState(token []byte) (backend.StateT, error)

	// TODO
	CacheSave(blobs map[string][]byte) error
	CacheGet(keys []string) (map[string][]byte, error)

	// CacheClient returns a CacheClient that can be used to interact
	// with the tstore cache.
	// CacheClient() CacheClient

	// InvClient returns a InvClient that can be used to interact with
	// a cached inventory.
	// TODO key must be prefix by the plugin ID
	InvClient(key string, encrypt bool) InvClient
}

// CacheClient provides a concurrency safe API for plugins to cache data in the
// key-value store. All operations are atomic.
//
// Cached data IS NOT be timetamped onto the Decred blockchain. Only data that
// can be re-created by walking the tlog trees should be cached.
//
// TODO reads and writes must be prefix by the plugin ID
type CacheClient interface {
	// Insert inserts a new entry into the cache store for each of the
	// provided key-value pairs.
	//
	// An ErrDuplicateKey is returned if a provided key already exists
	// in the key-value store.
	Insert(blobs map[string][]byte, encrypt bool) error

	// Update updates the provided key-value pairs in the cache.
	//
	// An ErrNotFound is returned if the caller attempts to update an
	// entry that does not exist.
	Update(blobs map[string][]byte, encrypt bool) error

	// Del deletes the provided entries from the cache.
	//
	// Keys that do not correspond to blob entries are ignored. An
	// error IS NOT returned.
	Del(keys []string) error

	// Get returns the cached blob for the provided key.
	//
	// An ErrNotFound error is returned if the key does not correspond
	// to an entry.
	Get(key string) ([]byte, error)

	// GetBatch returns the cached blobs for the provided keys.
	//
	// An entry will not exist in the returned map if for any blobs
	// that are not found. It is the responsibility of the caller to
	// ensure a blob was returned for all provided keys. An error is
	// not returned.
	GetBatch(keys []string) (map[string][]byte, error)
}

// InvClient provides a concurrency safe API that plugins can use to manage a
// cached inventory of tokens.
//
// Operations will be atomic if the client is initialized by a plugin write
// command. Operations WILL NOT be atomic if the client is initialized by a
// plugin read command.
//
// Data save to the inventory WILL NOT be timestamped onto the Decred
// blockchain.
//
// Bit flags are used to encode relevant data into inventory entries. An extra
// data field is also provided for the caller to use freely. The inventory can
// be queried by bit flags, by entry timestamp, or by providing a callback
// function that is invoked on each entry.
type InvClient interface {
	// Add adds a new entry to the inventory.
	Add(e inv.Entry) error

	// Update updates an inventory entry.
	Update(e inv.Entry) error

	// Del deletes an entry from the inventory.
	Del(token string) error

	// Get returns a page of tokens that match the provided filtering
	// criteria.
	Get(bits uint64, pageSize, pageNum uint32) ([]string, error)

	// GetMulti returns a page of tokens for each of the provided bits.
	// The bits are used as filtering criteria.
	//
	// The returned map is a map[bits][]token.
	GetMulti(bits []uint64, pageSize,
		pageNum uint32) (map[uint64][]string, error)

	// GetOrdered orders the entries from newest to oldest and returns
	// the specified page.
	GetOrdered(pageSize, pageNum uint32) ([]string, error)

	// GetAll returns all tokens in the inventory.
	GetAll() ([]string, error)

	// Iter iterates through the inventory and invokes the provided
	// callback on each inventory entry.
	Iter(callback func(e inv.Entry) error) error
}
