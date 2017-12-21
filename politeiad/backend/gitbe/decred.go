package gitbe

import "github.com/decred/politeia/politeiad/backend"

const decredPluginVersion = "1"

var (
	decredPlugin = backend.Plugin{
		ID:      "decred",
		Version: decredPluginVersion,
		Settings: []backend.PluginSetting{
			{
				Key:   "moo",
				Value: "blah",
			},
		},
	}
)
