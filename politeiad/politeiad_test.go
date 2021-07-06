// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "testing"

func TestParsePluginSetting(t *testing.T) {
	var tests = []struct {
		name string

		// Input
		setting string

		// Expected output
		err          bool
		pluginID     string
		settingKey   string
		settingValue string
	}{
		{
			"invalid setting not csv",
			"somepluginsetting",
			true,
			"",
			"",
			"",
		},
		{
			"invalid setting not enough fields",
			"pluginid,key",
			true,
			"",
			"",
			"",
		},
		{
			"invalid setting no closing brackets",
			"pluginid,key,[value1,value2",
			true,
			"",
			"",
			"",
		},
		{
			"invalid setting not json",
			"pluginid,key,[value1,value2,value3]",
			true,
			"",
			"",
			"",
		},
		{
			"single value normal",
			"pluginid,key,value",
			false,
			"pluginid",
			"key",
			"value",
		},
		{
			"single value mixed case",
			"pLugInID,KeY,vAlUe",
			false,
			"pluginid",
			"key",
			"vAlUe",
		},
		{
			"single value whitespaces",
			" pluginid, key, value",
			false,
			"pluginid",
			"key",
			"value",
		},
		{
			"multi value normal",
			`pluginid,key,["value1","value2","value3"]`,
			false,
			"pluginid",
			"key",
			`["value1","value2","value3"]`,
		},
		{
			"multi value whitespaces",
			`pluginid,key,["value1", "value2", "value3"]`,
			false,
			"pluginid",
			"key",
			`["value1","value2","value3"]`,
		},
		{
			"multi value with one entry",
			`pluginid,key,["value1"]`,
			false,
			"pluginid",
			"key",
			`["value1"]`,
		},
		{
			"multi value with escaped quotes",
			`pluginid,key,["value1","value2","\"","value4"]`,
			false,
			"pluginid",
			"key",
			`["value1","value2","\"","value4"]`,
		},
		{
			"multi value with comma value",
			`pluginid,key,["value1","value2",",","value4"]`,
			false,
			"pluginid",
			"key",
			`["value1","value2",",","value4"]`,
		},
	}
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			pluginID, ps, err := parsePluginSetting(v.setting)
			switch {
			case v.err && err == nil:
				t.Errorf("got nil error, expected failure for '%v'",
					v.setting)

			case v.err && err != nil:
				// Receieved the expected error output. Continue.

			case !v.err && err != nil:
				t.Errorf("got error '%v', want nil error", err)

			case pluginID != v.pluginID:
				t.Errorf("invalid plugin id: got %v, want %v",
					pluginID, v.pluginID)

			case ps.Key != v.settingKey:
				t.Errorf("invalid plugin setting key: got %v, want %v",
					ps.Key, v.settingKey)

			case ps.Value != v.settingValue:
				t.Errorf("invalid plugin setting value: got %v, want %v",
					ps.Value, v.settingValue)
			}
		})
	}
}
