package gitbe

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/dcrdata/dcrdata/dcrdataapi"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/backend"
)

var (
	decredPlugin = backend.Plugin{
		ID:      decredplugin.ID,
		Version: decredplugin.Version,
		Settings: []backend.PluginSetting{
			//{
			//	Key:   "dcrd",
			//	Value: "localhost:19109",
			//},
			//{
			//	Key:   "dcrduser",
			//	Value: "u",
			//},
			//{
			//	Key:   "dcrdpass",
			//	Value: "p",
			//},
			{
				Key:   "dcrdata",
				Value: "http://localhost:7777/",
			},
		},
	}
)

func bestBlock(route string) (*dcrdataapi.BlockDataBasic, error) {
	url := route + "api/block/best"
	log.Errorf("connecting to %v", url)
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var bdb dcrdataapi.BlockDataBasic
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bdb); err != nil {
		return nil, err
	}

	return &bdb, nil
}

func block(route string, block uint32) (*dcrdataapi.BlockDataBasic, error) {
	h := strconv.FormatUint(uint64(block), 10)
	url := route + "api/block/" + h
	log.Errorf("connecting to %v", url)
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var bdb dcrdataapi.BlockDataBasic
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bdb); err != nil {
		return nil, err
	}

	return &bdb, nil
}

func snapshot(route, hash string) ([]string, error) {
	url := route + "api/stake/pool/b/" + hash + "/full?sort=true"
	log.Errorf("connecting to %v", url)
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var tickets []string
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&tickets); err != nil {
		return nil, err
	}

	return tickets, nil
}
