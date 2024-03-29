// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
)

// HookT represents a plugin hook.
type HookT int

const (
	// HookTypeInvalid is an invalid plugin hook.
	HookTypeInvalid HookT = 0

	// HookTypeNewRecordPre is called before a new record is saved to
	// disk.
	HookTypeNewRecordPre HookT = 1

	// HookTypeNewRecordPost is called after a new record is saved to
	// disk.
	HookTypeNewRecordPost HookT = 2

	// HookTypeEditRecordPre is called before a record update is saved
	// to disk.
	HookTypeEditRecordPre HookT = 3

	// HookTypeEditRecordPost is called after a record update is saved
	// to disk.
	HookTypeEditRecordPost HookT = 4

	// HookTypeEditMetadataPre is called before a metadata update is
	// saved to disk.
	HookTypeEditMetadataPre HookT = 5

	// HookTypeEditMetadataPost is called after a metadata update is
	// saved to disk.
	HookTypeEditMetadataPost HookT = 6

	// HookTypeSetRecordStatusPre is called before a record status
	// change is saved to disk.
	HookTypeSetRecordStatusPre HookT = 7

	// HookTypeSetRecordStatusPost is called after a record status
	// change is saved to disk.
	HookTypeSetRecordStatusPost HookT = 8

	// HookTypePluginPre is called before a plugin command is executed.
	HookTypePluginPre HookT = 9

	// HookTypePluginPost is called after a plugin command is executed.
	HookTypePluginPost HookT = 10

	// HookTypeLast unit test only
	HookTypeLast HookT = 11
)

var (
	// Hooks contains human readable descriptions of the plugin hooks.
	Hooks = map[HookT]string{
		HookTypeInvalid:             "invalid hook",
		HookTypeNewRecordPre:        "new record pre",
		HookTypeNewRecordPost:       "new record post",
		HookTypeEditRecordPre:       "edit record pre",
		HookTypeEditRecordPost:      "edit record post",
		HookTypeEditMetadataPre:     "edit metadata pre",
		HookTypeEditMetadataPost:    "edit metadata post",
		HookTypeSetRecordStatusPre:  "set record status pre",
		HookTypeSetRecordStatusPost: "set record status post",
		HookTypePluginPre:           "plugin pre",
		HookTypePluginPost:          "plugin post",
	}
)

// HookNewRecordPre is the payload for the pre new record hook.
type HookNewRecordPre struct {
	Metadata []backend.MetadataStream `json:"metadata"`
	Files    []backend.File           `json:"files"`
}

// HookNewRecordPost is the payload for the post new record hook.
type HookNewRecordPost struct {
	Metadata       []backend.MetadataStream `json:"metadata"`
	Files          []backend.File           `json:"files"`
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
}

// HookEditRecord is the payload for the pre and post edit record hooks.
type HookEditRecord struct {
	Record backend.Record `json:"record"` // Record pre update

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	Metadata       []backend.MetadataStream `json:"metadata"`
	Files          []backend.File           `json:"files"`
}

// HookEditMetadata is the payload for the pre and post edit metadata hooks.
type HookEditMetadata struct {
	Record backend.Record `json:"record"` // Record pre update

	// Updated fields
	Metadata []backend.MetadataStream `json:"metadata"`
}

// HookSetRecordStatus is the payload for the pre and post set record status
// hooks.
type HookSetRecordStatus struct {
	Record backend.Record `json:"record"` // Record pre update

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	Metadata       []backend.MetadataStream `json:"metadata"`
}

// HookPluginPre is the payload for the pre plugin hook.
type HookPluginPre struct {
	Token    []byte `json:"token"`
	PluginID string `json:"pluginid"`
	Cmd      string `json:"cmd"`
	Payload  string `json:"payload"`
}

// HookPluginPost is the payload for the post plugin hook. The post plugin hook
// includes the plugin reply.
type HookPluginPost struct {
	PluginID string `json:"pluginid"`
	Cmd      string `json:"cmd"`
	Payload  string `json:"payload"`
	Reply    string `json:"reply"`
}

// PluginClient provides an API for a tstore instance to use when interacting
// with a plugin. All tstore plugins must implement the PluginClient interface.
type PluginClient interface {
	// Setup performs any required plugin setup.
	Setup() error

	// Cmd executes a plugin command.
	Cmd(token []byte, cmd, payload string) (string, error)

	// Hook executes a plugin hook.
	Hook(h HookT, payload string) error

	// Fsck performs a plugin file system check. The plugin is
	// provided with the tokens for all records in the backend.
	Fsck(tokens [][]byte) error

	// Settings returns the plugin settings.
	Settings() []backend.PluginSetting
}

// TstoreClient provides an API for plugins to interact with a tstore instance.
// Plugins are allowed to save, delete, and get plugin data to/from the tstore
// backend. Editing plugin data is not allowed.
type TstoreClient interface {
	// BlobSave saves a BlobEntry to the tstore instance. The BlobEntry
	// will be encrypted prior to being written to disk if the record
	// is unvetted. The digest of the data, i.e. BlobEntry.Digest, can
	// be thought of as the blob ID that can be used to get/del the
	// blob from tstore.
	BlobSave(token []byte, be store.BlobEntry) error

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
	// oldest to newest. If a record is vetted, only the digests of
	// vetted blobs will be returned.
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

	// RecordState returns whether the record is unvetted or vetted.
	RecordState(token []byte) (backend.StateT, error)

	// CachePut saves the provided key-value pairs to the key-value store. It
	// prefixes the keys with the plugin ID in order to limit the access of the
	// plugins only to the data they own.
	CachePut(blobs map[string][]byte, encrypt bool) error

	// CacheDel deletes the provided blobs from the key-value store. This
	// operation is performed atomically. It prefixes the keys with the plugin
	// ID in order to limit the access of the plugins only to the data they own.
	CacheDel(keys []string) error

	// CacheGet returns blobs from the key-value store for the provided keys. An
	// entry will not exist in the returned map if for any blobs that are not
	// found. It is the responsibility of the caller to ensure a blob
	// was returned for all provided keys. It prefixes the keys with the plugin
	// ID in order to limit the access of the plugins only to the data they own.
	CacheGet(keys []string) (map[string][]byte, error)
}
