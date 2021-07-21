// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

/* TODO add hooks back in
// hookRecordNewPre adds plugin specific validation onto the tstore backend
// RecordNew method.
func (p *ticketVotePlugin) hookRecordNewPre(payload string) error {
	var rn plugins.RecordNew
	err := json.Unmarshal([]byte(payload), &rn)
	if err != nil {
		return err
	}

	// Verify vote metadata
	return p.voteMetadataVerify(rn.Files)
}

// hookRecordEditPre adds plugin specific validation onto the tstore backend
// RecordEdit method.
func (p *ticketVotePlugin) hookRecordEditPre(payload string) error {
	var er plugins.RecordEdit
	err := json.Unmarshal([]byte(payload), &er)
	if err != nil {
		return err
	}

	// Verify vote metadata
	return p.voteMetadataVerifyOnEdits(er.Record, er.Files)
}

// hookRecordSetStatusPre adds plugin specific validation onto the tstore
// backend RecordSetStatus method.
func (p *ticketVotePlugin) hookRecordSetStatusPre(payload string) error {
	var rss plugins.RecordSetStatus
	err := json.Unmarshal([]byte(payload), &rss)
	if err != nil {
		return err
	}

	// Verify vote metadata
	return p.voteMetadataVerifyOnStatusChange(rss.RecordMetadata.Status,
		rss.Record.Files)
}

// hookRecordSetStatusPost caches plugin data from the tstore backend
// RecordSetStatus method.
func (p *ticketVotePlugin) hookRecordSetStatusPost(payload string) error {
	var rss plugins.RecordSetStatus
	err := json.Unmarshal([]byte(payload), &rss)
	if err != nil {
		return err
	}

	// Ticketvote caches only need to be updated for vetted records
	if rss.RecordMetadata.State == backend.StateUnvetted {
		return nil
	}

	// Update the inventory cache
	switch rss.RecordMetadata.Status {
	case backend.StatusPublic:
		// Add to inventory
		p.inventoryAdd(rss.RecordMetadata.Token,
			ticketvote.VoteStatusUnauthorized)
	case backend.StatusCensored, backend.StatusArchived:
		// These statuses do not allow for a vote. Mark as ineligible.
		p.inventoryUpdate(rss.RecordMetadata.Token,
			ticketvote.VoteStatusIneligible)
	}

	// Update cached vote metadata
	return p.voteMetadataCacheOnStatusChange(rss.RecordMetadata.Token,
		rss.RecordMetadata.State, rss.RecordMetadata.Status, rss.Record.Files)
}

// linkByVerify verifies that the provided link by timestamp meets all
// ticketvote plugin requirements. See the ticketvote VoteMetadata structure
// for more details on the link by timestamp.
func (p *ticketVotePlugin) linkByVerify(linkBy int64) error {
	if linkBy == 0 {
		// LinkBy as not been set
		return nil
	}

	// Min and max link by periods are a ticketvote plugin setting
	min := time.Now().Unix() + p.linkByPeriodMin
	max := time.Now().Unix() + p.linkByPeriodMax
	switch {
	case linkBy < min:
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeLinkByInvalid),
			ErrorContext: fmt.Sprintf("linkby %v is less than min required of %v",
				linkBy, min),
		}
	case linkBy > max:
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeLinkByInvalid),
			ErrorContext: fmt.Sprintf("linkby %v is more than max allowed of %v",
				linkBy, max),
		}
	}

	return nil
}

// linkToVerify verifies that the provided link to meets all ticketvote plugin
// requirements. See the ticketvote VoteMetadata structure for more details on
// the link to field.
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
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeLinkToInvalid),
			ErrorContext: fmt.Sprintf("record status is invalid: got %v, want %v",
				backend.Statuses[r.RecordMetadata.Status],
				backend.Statuses[backend.StatusPublic]),
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

// linkToVerifyOnEdits runs LinkTo validation that is specific to record edits.
func (p *ticketVotePlugin) linkToVerifyOnEdits(r backend.Record, newFiles []backend.File) error {
	// The LinkTo field is not allowed to change once the record has
	// become public.
	if r.RecordMetadata.State != backend.StateVetted {
		// Not vetted. Nothing to do.
		return nil
	}
	var (
		oldLinkTo string
		newLinkTo string
	)
	vm, err := voteMetadataDecode(r.Files)
	if err != nil {
		return err
	}
	// Vote metadata is optional so one may not exist
	if vm != nil {
		oldLinkTo = vm.LinkTo
	}
	vm, err = voteMetadataDecode(newFiles)
	if err != nil {
		return err
	}
	if vm != nil {
		newLinkTo = vm.LinkTo
	}
	if newLinkTo != oldLinkTo {
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeLinkToInvalid),
			ErrorContext: fmt.Sprintf("linkto cannot change on vetted record: "+
				"got '%v', want '%v'", newLinkTo, oldLinkTo),
		}
	}
	return nil
}

// linkToVerifyOnStatusChange runs LinkTo validation that is specific to record
// status changes.
func (p *ticketVotePlugin) linkToVerifyOnStatusChange(status backend.StatusT, vm ticketvote.VoteMetadata) error {
	if vm.LinkTo == "" {
		// Link to not set. Nothing to do.
		return nil
	}

	// Verify that the deadline to link to this record has not expired.
	// We only need to do this when a record is being made public since
	// the submissions list of the parent record is only updated for
	// public records.
	if status != backend.StatusPublic {
		// Not being made public. Nothing to do.
		return nil
	}

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
		return fmt.Errorf("vote metadata does not exist on parent record %v",
			vm.LinkTo)
	}
	if time.Now().Unix() > vmParent.LinkBy {
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeLinkToInvalid),
			ErrorContext: "parent record linkby has expired",
		}
	}

	return nil
}

// voteMetadataVerify decodes the VoteMetadata from the provided files and
// verifies that it meets the ticketvote plugin requirements. Vote metadata is
// optional so one may not exist.
func (p *ticketVotePlugin) voteMetadataVerify(files []backend.File) error {
	// Decode vote metadata. The vote metadata is optional so one may
	// not exist.
	vm, err := voteMetadataDecode(files)
	if err != nil {
		return err
	}
	if vm == nil {
		// Vote metadata not found. Nothing to do.
		return nil
	}

	// Verify vote metadata fields are sane
	switch {
	case vm.LinkBy == 0 && vm.LinkTo == "":
		// Vote metadata is empty. This is not allowed.
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
		// LinkBy has been set. Verify that is meets plugin requirements.
		err := p.linkByVerify(vm.LinkBy)
		if err != nil {
			return err
		}

	case vm.LinkTo != "":
		// LinkTo has been set. Verify that is meets plugin requirements.
		err := p.linkToVerify(vm.LinkTo)
		if err != nil {
			return err
		}
	}

	return nil
}

// voteMetadataVerifyOnEdits runs vote metadata validation that is specific to
// record edits.
func (p *ticketVotePlugin) voteMetadataVerifyOnEdits(r backend.Record, newFiles []backend.File) error {
	// Verify LinkTo has not changed. This must be run even if a vote
	// metadata is not present.
	err := p.linkToVerifyOnEdits(r, newFiles)
	if err != nil {
		return err
	}

	// Decode vote metadata. The vote metadata is optional so one may not
	// exist.
	vm, err := voteMetadataDecode(newFiles)
	if err != nil {
		return err
	}
	if vm == nil {
		// Vote metadata not found. Nothing to do.
		return nil
	}

	// Verify LinkBy
	err = p.linkByVerify(vm.LinkBy)
	if err != nil {
		return err
	}

	// The LinkTo does not need to be validated since we have already
	// confirmed that it has not changed from the previous record
	// version and it would have already been validated when the record
	// was originally submitted. It should not be possible for it to be
	// invalid at this point.

	return nil
}

// voteMetadataVerifyOnStatusChange runs vote metadata validation that is
// specific to record status changes.
func (p *ticketVotePlugin) voteMetadataVerifyOnStatusChange(status backend.StatusT, files []backend.File) error {
	// Decode vote metadata. Vote metadata is optional so one may not
	// exist.
	vm, err := voteMetadataDecode(files)
	if err != nil {
		return err
	}
	if vm == nil {
		// Vote metadata not found. Nothing to do.
		return nil
	}

	// Verify LinkTo
	err = p.linkToVerifyOnStatusChange(status, *vm)
	if err != nil {
		return err
	}

	// Verify LinkBy
	return p.linkByVerify(vm.LinkBy)
}

// voteMetadataCacheOnStatusChange performs vote metadata cache updates after
// a record status change.
func (p *ticketVotePlugin) voteMetadataCacheOnStatusChange(token string, state backend.StateT, status backend.StatusT, files []backend.File) error {
	// Decode vote metadata. Vote metadata is optional so one may not
	// exist.
	vm, err := voteMetadataDecode(files)
	if err != nil {
		return err
	}
	if vm == nil {
		// Vote metadata doesn't exist. Nothing to do.
		return nil
	}
	if vm.LinkTo == "" {
		// LinkTo not set. Nothing to do.
		return nil
	}

	// LinkTo has been set. Check if the status change requires the
	// submissions list of the linked record to be updated.
	var (
		parentToken = vm.LinkTo
		childToken  = token
	)
	switch {
	case state == backend.StateUnvetted:
		// We do not update the submissions cache for unvetted records.
		// Do nothing.

	case status == backend.StatusPublic:
		// Record has been made public. Add child token to parent's
		// submissions list.
		err := p.submissionsCacheAdd(parentToken, childToken)
		if err != nil {
			return fmt.Errorf("submissionsFromCacheAdd: %v", err)
		}

	case status == backend.StatusCensored:
		// Record has been censored. Delete child token from parent's
		// submissions list.
		err := p.submissionsCacheDel(parentToken, childToken)
		if err != nil {
			return fmt.Errorf("submissionsCacheDel: %v", err)
		}
	}

	return nil
}

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
*/
