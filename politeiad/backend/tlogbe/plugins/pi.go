// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"encoding/base64"

	"github.com/decred/politeia/plugins/pi"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
)

var (
	_ tlogbe.Plugin = (*piPlugin)(nil)
)

type piPlugin struct{}

func (p *piPlugin) Setup() error {
	log.Tracef("pi Setup")

	return nil
}

func (p *piPlugin) Cmd(cmd, payload string) (string, error) {
	log.Tracef("pi Cmd: %v %v", cmd, payload)

	return "", nil
}

func (p *piPlugin) hookNewRecordPre(payload string) error {
	nrp, err := tlogbe.DecodeNewRecordPre([]byte(payload))
	if err != nil {
		return err
	}

	// Decode the ProposalMetadata
	// TODO pickup here
	var pm *pi.ProposalMetadata
	for _, v := range nrp.Files {
		if v.Name == pi.FilenameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			pm, err = pi.DecodeProposalMetadata(b)
			if err != nil {
				return err
			}
			break
		}
	}
	if pm == nil {
	}

	return nil
}

func (p *piPlugin) Hook(h tlogbe.HookT, payload string) error {
	log.Tracef("pi Hook: %v", tlogbe.Hooks[h])

	switch h {
	case tlogbe.HookNewRecordPre:
		return p.hookNewRecordPre(payload)
	}

	return nil
}

func (p *piPlugin) Fsck() error {
	log.Tracef("pi Fsck")

	return nil
}

func NewPiPlugin() *piPlugin {
	return &piPlugin{}
}
