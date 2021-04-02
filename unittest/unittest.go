// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package unittest

import (
	"fmt"
	"reflect"
)

// TestGenericConstMap tests a map of an error constant type and verifies that
// the error numbers are consecutive and represented in the human readable map.
// This function is for UT only.
func TestGenericConstMap(errorsMap interface{}, lastError uint64) error {
	if reflect.TypeOf(errorsMap).Kind() != reflect.Map {
		return fmt.Errorf("errorsMap not a map: %T", errorsMap)
	}
	val := reflect.ValueOf(errorsMap)

	leftover := make(map[uint64]struct{}, len(val.MapKeys()))
	for i := uint64(0); i < uint64(len(val.MapKeys())); i++ {
		leftover[i] = struct{}{}

	}
	for _, mapKey := range val.MapKeys() {
		var key uint64
		switch mapKey.Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
			reflect.Uint64:
			key = mapKey.Uint()
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
			reflect.Int64:
			key = uint64(mapKey.Int())
		default:
			return fmt.Errorf("unsupported key type: %v",
				mapKey.Kind())
		}
		delete(leftover, key)
	}
	if len(leftover) != 0 {
		return fmt.Errorf("leftover length not 0: %v", leftover)
	}
	if len(val.MapKeys()) != int(lastError) {
		return fmt.Errorf("someone added a map code without adding a "+
			"human readable description. Got %v, want %v",
			len(val.MapKeys()), lastError)
	}

	return nil
}
