// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// voteMetadataDecode decodes and returns the VoteMetadata from the
// provided backend files. If a VoteMetadata is not found, nil is returned.
func voteMetadataDecode(files []backend.File) (*ticketvote.VoteMetadata, error) {
	var voteMD *ticketvote.VoteMetadata
	for _, v := range files {
		if v.Name == ticketvote.FileNameVoteMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			var m ticketvote.VoteMetadata
			err = json.Unmarshal(b, &m)
			if err != nil {
				return nil, err
			}
			voteMD = &m
			break
		}
	}
	return voteMD, nil
}

func (p *ticketVotePlugin) linkByVerify(linkBy int64) error {
	if linkBy == 0 {
		// LinkBy as not been set
		return nil
	}
	min := time.Now().Unix() + p.linkByPeriodMin
	max := time.Now().Unix() + p.linkByPeriodMax
	switch {
	case linkBy < min:
		e := fmt.Sprintf("linkby %v is less than min required of %v",
			linkBy, min)
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    int(ticketvote.ErrorCodeLinkByInvalid),
			ErrorContext: e,
		}
	case linkBy > max:
		e := fmt.Sprintf("linkby %v is more than max allowed of %v",
			linkBy, max)
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    int(ticketvote.ErrorCodeLinkByInvalid),
			ErrorContext: e,
		}
	}
	return nil
}

func (p *ticketVotePlugin) linkToVerify(linkTo string) error {
	// LinkTo must be a public record
	token, err := tokenDecode(linkTo)
	if err != nil {
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    int(ticketvote.ErrorCodeLinkToInvalid),
			ErrorContext: "invalid hex",
		}
	}
	r, err := p.backend.GetVetted(token, "")
	if err != nil {
		if errors.Is(err, backend.ErrRecordNotFound) {
			return backend.PluginError{
				PluginID:     ticketvote.PluginID,
				ErrorCode:    int(ticketvote.ErrorCodeLinkToInvalid),
				ErrorContext: "record not found",
			}
		}
		return err
	}
	if r.RecordMetadata.Status != backend.MDStatusVetted {
		e := fmt.Sprintf("record status is invalid: got %v, want %v",
			backend.MDStatus[r.RecordMetadata.Status],
			backend.MDStatus[backend.MDStatusVetted])
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    int(ticketvote.ErrorCodeLinkToInvalid),
			ErrorContext: e,
		}
	}

	// LinkTo must be a runoff vote parent record, i.e. has specified
	// a LinkBy deadline.
	parentVM, err := voteMetadataDecode(r.Files)
	if err != nil {
		return err
	}
	if parentVM == nil || parentVM.LinkBy == 0 {
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    int(ticketvote.ErrorCodeLinkToInvalid),
			ErrorContext: "record not a runoff vote parent",
		}
	}

	// The LinkBy deadline must not be expired
	if time.Now().Unix() > parentVM.LinkBy {
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    int(ticketvote.ErrorCodeLinkToInvalid),
			ErrorContext: "parent record linkby deadline has expired",
		}
	}

	// The runoff vote parent record must have been approved in a vote.
	vs, err := p.summaryByToken(token)
	if err != nil {
		return err
	}
	if !vs.Approved {
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    int(ticketvote.ErrorCodeLinkToInvalid),
			ErrorContext: "parent record vote is not approved",
		}
	}

	return nil
}

func (p *ticketVotePlugin) voteMetadataVerify(vm ticketvote.VoteMetadata) error {
	switch {
	case vm.LinkBy == 0 && vm.LinkTo == "":
		// Vote metadata is empty
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    int(ticketvote.ErrorCodeVoteMetadataInvalid),
			ErrorContext: "metadata is empty",
		}

	case vm.LinkBy != 0 && vm.LinkTo != "":
		// LinkBy and LinkTo cannot both be set
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    int(ticketvote.ErrorCodeVoteMetadataInvalid),
			ErrorContext: "cannot set both linkby and linkto",
		}

	case vm.LinkBy != 0:
		err := p.linkByVerify(vm.LinkBy)
		if err != nil {
			return err
		}

	case vm.LinkTo != "":
		err := p.linkToVerify(vm.LinkTo)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *ticketVotePlugin) hookNewRecordPre(payload string) error {
	var nr plugins.HookNewRecordPre
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	// Verify the vote metadata if the record contains one
	vm, err := voteMetadataDecode(nr.Files)
	if err != nil {
		return err
	}
	if vm != nil {
		err = p.voteMetadataVerify(*vm)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *ticketVotePlugin) hookEditRecordPre(payload string) error {
	var er plugins.HookEditRecord
	err := json.Unmarshal([]byte(payload), &er)
	if err != nil {
		return err
	}

	// The LinkTo field is not allowed to change once the record has
	// become public. If this is a vetted record, verify that any
	// previously set LinkTo has not changed.
	if er.State == plugins.RecordStateVetted {
		var (
			oldLinkTo string
			newLinkTo string
		)
		vm, err := voteMetadataDecode(er.Current.Files)
		if err != nil {
			return err
		}
		if vm != nil {
			oldLinkTo = vm.LinkTo
		}
		vm, err = voteMetadataDecode(er.Files)
		if err != nil {
			return err
		}
		if vm != nil {
			newLinkTo = vm.LinkTo
		}
		if newLinkTo != oldLinkTo {
			e := fmt.Sprintf("linkto cannot change on vetted record: "+
				"got '%v', want '%v'", newLinkTo, oldLinkTo)
			return backend.PluginError{
				PluginID:     ticketvote.PluginID,
				ErrorCode:    int(ticketvote.ErrorCodeLinkToInvalid),
				ErrorContext: e,
			}
		}
	}

	// Verify LinkBy if one was included. The VoteMetadata is optional
	// so the record may not contain one.
	vm, err := voteMetadataDecode(er.Files)
	if err != nil {
		return err
	}
	if vm != nil {
		err = p.linkByVerify(vm.LinkBy)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *ticketVotePlugin) hookSetRecordStatusPost(payload string) error {
	var srs plugins.HookSetRecordStatus
	err := json.Unmarshal([]byte(payload), &srs)
	if err != nil {
		return err
	}

	// Check if the LinkTo has been set
	vm, err := voteMetadataDecode(srs.Current.Files)
	if err != nil {
		return err
	}
	if vm != nil && vm.LinkTo != "" {
		// LinkTo has been set. Check if the status change requires the
		// linked from list of the linked record to be updated.
		var (
			parentToken = vm.LinkTo
			childToken  = srs.RecordMetadata.Token
		)
		switch srs.RecordMetadata.Status {
		case backend.MDStatusVetted:
			// Record has been made public. Add child token to parent's
			// linked from list.
			err := p.linkedFromCacheAdd(parentToken, childToken)
			if err != nil {
				return fmt.Errorf("linkedFromCacheAdd: %v", err)
			}
		case backend.MDStatusCensored:
			// Record has been censored. Delete child token from parent's
			// linked from list.
			err := p.linkedFromCacheDel(parentToken, childToken)
			if err != nil {
				return fmt.Errorf("linkedFromCacheDel: %v", err)
			}
		}
	}

	return nil
}
