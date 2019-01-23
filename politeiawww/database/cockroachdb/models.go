// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

// KeyValue describes a key-value model for storing an encoded payload by key.
type KeyValue struct {
	Key     string `gorm:"primary_key"` // Primary key
	Payload []byte `gorm:"not null"`    // Byte slice encoded payload
}

// TableName returns the table name for the KeyValue model.
func (KeyValue) TableName() string {
	return tableKeyValue
}
