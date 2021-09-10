// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package unittest

import (
	"reflect"

	"github.com/pkg/errors"
)

// TestGenericConstMap tests a map of an error constant type and verifies that
// the error numbers are consecutive and represented in the human readable map.
// This function is for unit tests only.
func TestGenericConstMap(errorsMap interface{}, lastError uint64) error {
	if reflect.TypeOf(errorsMap).Kind() != reflect.Map {
		return errors.Errorf("errorsMap not a map: %T", errorsMap)
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
			return errors.Errorf("unsupported key type: %v",
				mapKey.Kind())
		}
		delete(leftover, key)
	}
	if len(leftover) != 0 {
		return errors.Errorf("leftover length not 0: %v", leftover)
	}
	if len(val.MapKeys()) != int(lastError) {
		return errors.Errorf("someone added a map code without adding a "+
			"human readable description. Got %v, want %v",
			len(val.MapKeys()), lastError)
	}

	return nil
}

// CompareStructFieldCounts compares the number of fields in the two provided
// structs and returns an error if the number of fields is not the same. This
// function does not check that the field types match.
//
// This function can be used to test that a local struct matches an API spec
// struct.
func CompareStructFieldCounts(struct1, struct2 interface{}) error {
	value1 := reflect.ValueOf(struct1)
	value2 := reflect.ValueOf(struct2)

	// Verify that both objects are structs
	if value1.Kind().String() != "struct" {
		return errors.Errorf("object 1 is not a struct")
	}
	if value2.Kind().String() != "struct" {
		return errors.Errorf("object 2 is not a struct")
	}

	// Verify that both structs have the same number of fields
	if value1.NumField() != value2.NumField() {
		return errors.Errorf("structs have a different number of "+
			"fields: struct 1 has %v fields, struct 2 has %v fields",
			value1.NumField(), value2.NumField())
	}

	return nil
}

// CompareStructFields compares the fields of two different structs and returns
// an error if the number of fields do not match or the field types do not
// match. The fields of the structs must be listed in the order in the struct
// definitions.
//
// This function can be used to test that a local struct has the same number
// of fields as an API spec struct.
func CompareStructFields(struct1, struct2 interface{}) error {
	value1 := reflect.ValueOf(struct1)
	value2 := reflect.ValueOf(struct2)

	// Verify that both objects are structs
	if value1.Kind().String() != "struct" {
		return errors.Errorf("object 1 is not a struct")
	}
	if value2.Kind().String() != "struct" {
		return errors.Errorf("object 2 is not a struct")
	}

	// Verify that both structs have the same number of fields
	if value1.NumField() != value2.NumField() {
		return errors.Errorf("structs have a different number of "+
			"fields: struct 1 has %v fields, struct 2 has %v fields",
			value1.NumField(), value2.NumField())
	}

	// Verify that the fields are the same types
	for i := 0; i < value1.NumField(); i++ {
		fieldType1 := value1.Field(i).Type().String()
		fieldType2 := value2.Field(i).Type().String()
		if fieldType1 != fieldType2 {
			return errors.Errorf("field in struct 1 (%v) does not "+
				"match field in struct 2 (%v)", fieldType1, fieldType2)
		}
	}

	return nil
}
