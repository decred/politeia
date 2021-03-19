// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// voteMetadataDecode decodes and returns the VoteMetadata from the
// provided backend files. If a VoteMetadata is not found, nil is returned.
func voteMetadataDecode(files []backend.File) (*ticketvote.VoteMetadata, error) {
	var voteMD *ticketvote.VoteMetadata
	for _, v := range files {
		if v.Name != ticketvote.FileNameVoteMetadata {
			continue
		}
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
			ErrorCode:    uint32(ticketvote.ErrorCodeLinkByInvalid),
			ErrorContext: e,
		}
	case linkBy > max:
		e := fmt.Sprintf("linkby %v is more than max allowed of %v",
			linkBy, max)
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeLinkByInvalid),
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
			ErrorCode:    uint32(ticketvote.ErrorCodeLinkToInvalid),
			ErrorContext: err.Error(),
		}
	}
	r, err := p.recordAbridged(token)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return backend.PluginError{
				PluginID:     ticketvote.PluginID,
				ErrorCode:    uint32(ticketvote.ErrorCodeLinkToInvalid),
				ErrorContext: "record not found",
			}
		}
		return err
	}
	if r.RecordMetadata.Status != backend.StatusPublic {
		e := fmt.Sprintf("record status is invalid: got %v, want %v",
			backend.Statuses[r.RecordMetadata.Status],
			backend.Statuses[backend.StatusPublic])
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeLinkToInvalid),
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
			ErrorCode:    uint32(ticketvote.ErrorCodeLinkToInvalid),
			ErrorContext: "record not a runoff vote parent",
		}
	}

	// The LinkBy deadline must not be expired
	if time.Now().Unix() > parentVM.LinkBy {
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeLinkToInvalid),
			ErrorContext: "parent record linkby deadline has expired",
		}
	}

	// The runoff vote parent record must have been approved in a vote.
	vs, err := p.summaryByToken(token)
	if err != nil {
		return err
	}
	if vs.Status != ticketvote.VoteStatusApproved {
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeLinkToInvalid),
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
			ErrorCode:    uint32(ticketvote.ErrorCodeVoteMetadataInvalid),
			ErrorContext: "metadata is empty",
		}

	case vm.LinkBy != 0 && vm.LinkTo != "":
		// LinkBy and LinkTo cannot both be set
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeVoteMetadataInvalid),
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
	if er.Record.RecordMetadata.State == backend.StateVetted {
		var (
			oldLinkTo string
			newLinkTo string
		)
		vm, err := voteMetadataDecode(er.Record.Files)
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
				ErrorCode:    uint32(ticketvote.ErrorCodeLinkToInvalid),
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

func (p *ticketVotePlugin) hookSetRecordStatusPre(payload string) error {
	var srs plugins.HookSetRecordStatus
	err := json.Unmarshal([]byte(payload), &srs)
	if err != nil {
		return err
	}

	// Check if the LinkTo has been set
	vm, err := voteMetadataDecode(srs.Record.Files)
	if err != nil {
		return err
	}
	if vm != nil && vm.LinkTo != "" {
		// LinkTo has been set. Verify that the deadline to link to this
		// record has not expired. We only need to do this when a record
		// is being made public since the submissions list of the parent
		// record is only updated for public records. This update occurs
		// in the set status post hook.
		switch srs.RecordMetadata.Status {
		case backend.StatusPublic:
			// Get the parent record
			token, err := tokenDecode(vm.LinkTo)
			if err != nil {
				return err
			}
			r, err := p.recordAbridged(token)
			if err != nil {
				return err
			}

			// Verify linkby has not expired
			vmParent, err := voteMetadataDecode(r.Files)
			if err != nil {
				return err
			}
			if vmParent == nil {
				e := fmt.Sprintf("vote metadata does not exist on parent record %v",
					srs.RecordMetadata.Token)
				panic(e)
			}
			if time.Now().Unix() > vmParent.LinkBy {
				return backend.PluginError{
					PluginID:     ticketvote.PluginID,
					ErrorCode:    uint32(ticketvote.ErrorCodeLinkToInvalid),
					ErrorContext: "parent record linkby has expired",
				}
			}

		default:
			// Nothing to do
		}
	}

	return nil
}

func (p *ticketVotePlugin) hookSetRecordStatusPost(treeID int64, payload string) error {
	var srs plugins.HookSetRecordStatus
	err := json.Unmarshal([]byte(payload), &srs)
	if err != nil {
		return err
	}

	// Ticketvote caches only need to be updated for vetted records
	if srs.RecordMetadata.State == backend.StateUnvetted {
		return nil
	}

	// Update the inventory cache
	var (
		oldStatus = srs.Record.RecordMetadata.Status
		newStatus = srs.RecordMetadata.Status
	)
	switch newStatus {
	case backend.StatusPublic:
		// Add to inventory
		p.inventoryAdd(srs.RecordMetadata.Token,
			ticketvote.VoteStatusUnauthorized)
	case backend.StatusCensored, backend.StatusArchived:
		// These statuses do not allow for a vote. Mark as ineligible.
		p.inventoryUpdate(srs.RecordMetadata.Token,
			ticketvote.VoteStatusIneligible)
	}

	// Update the submissions cache if the linkto has been set.
	vm, err := voteMetadataDecode(srs.Record.Files)
	if err != nil {
		return err
	}
	if vm != nil && vm.LinkTo != "" {
		// LinkTo has been set. Check if the status change requires the
		// submissions list of the linked record to be updated.
		var (
			parentToken = vm.LinkTo
			childToken  = srs.RecordMetadata.Token
		)
		switch newStatus {
		case backend.StatusPublic:
			// Record has been made public. Add child token to parent's
			// submissions list.
			err := p.submissionsCacheAdd(parentToken, childToken)
			if err != nil {
				return fmt.Errorf("submissionsFromCacheAdd: %v", err)
			}
		case backend.StatusCensored:
			// Record has been censored. Delete child token from parent's
			// submissions list. We only need to do this if the record is
			// vetted.
			if oldStatus == backend.StatusPublic {
				err := p.submissionsCacheDel(parentToken, childToken)
				if err != nil {
					return fmt.Errorf("submissionsCacheDel: %v", err)
				}
			}
		}
	}

	return nil
}
