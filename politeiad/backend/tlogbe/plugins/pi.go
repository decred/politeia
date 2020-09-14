// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/decred/politeia/plugins/pi"
	"github.com/decred/politeia/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
)

const (
	// Filenames of memoized data saved to the data dir.
	filenameLinkedFrom = "{token}-linkedfrom.json"
)

var (
	_ tlogbe.Plugin = (*piPlugin)(nil)
)

// piPlugin satisfies the Plugin interface.
type piPlugin struct {
	sync.Mutex
	backend *tlogbe.TlogBackend

	// dataDir is the pi plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string
}

func isRFP(pm pi.ProposalMetadata) bool {
	return pm.LinkBy != 0
}

// proposalMetadataFromFiles parses and returns the ProposalMetadata from the
// provided files. If a ProposalMetadata is not found, nil is returned.
func proposalMetadataFromFiles(files []backend.File) (*pi.ProposalMetadata, error) {
	var pm *pi.ProposalMetadata
	for _, v := range files {
		if v.Name == pi.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			pm, err = pi.DecodeProposalMetadata(b)
			if err != nil {
				return nil, err
			}
		}
	}
	return pm, nil
}

// TODO saving the linkedFrom to the filesystem is not scalable between
// multiple politeiad instances. The plugin needs to have a tree that can be
// used to share state between the different politeiad instances.

// linkedFrom is the the structure that is updated and cached for proposal A
// when proposal B links to proposal A. The list contains all proposals that
// have linked to proposal A. The linked from list will only contain public
// proposals.
//
// Example: an RFP proposal's linked from list will contain all public RFP
// submissions since they have all linked to the RFP proposal.
type linkedFrom struct {
	Tokens map[string]struct{} `json:"tokens"`
}

func (p *piPlugin) cachedLinkedFromPath(token string) string {
	fn := strings.Replace(filenameLinkedFrom, "{token}", token, 1)
	return filepath.Join(p.dataDir, fn)
}

// This function must be called WITH the lock held.
func (p *piPlugin) cachedLinkedFromLocked(token string) (*linkedFrom, error) {
	fp := p.cachedLinkedFromPath(token)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist
			return nil, errRecordNotFound
		}
	}

	var lf linkedFrom
	err = json.Unmarshal(b, &lf)
	if err != nil {
		return nil, err
	}

	return &lf, nil
}

func (p *piPlugin) cachedLinkedFrom(token string) (*linkedFrom, error) {
	p.Lock()
	defer p.Unlock()

	return p.cachedLinkedFromLocked(token)
}

func (p *piPlugin) cachedLinkedFromAdd(parentToken, childToken string) error {
	p.Lock()
	defer p.Unlock()

	// Get existing linked from list
	lf, err := p.cachedLinkedFromLocked(parentToken)
	if err == errRecordNotFound {
		// List doesn't exist. Create a new one.
		lf = &linkedFrom{
			Tokens: make(map[string]struct{}, 0),
		}
	} else if err != nil {
		return fmt.Errorf("cachedLinkedFromLocked %v: %v", parentToken, err)
	}

	// Update list
	lf.Tokens[childToken] = struct{}{}

	// Save list
	b, err := json.Marshal(lf)
	if err != nil {
		return err
	}
	fp := p.cachedLinkedFromPath(parentToken)
	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return fmt.Errorf("WriteFile: %v", err)
	}

	return nil
}

func (p *piPlugin) cachedLinkedFromDel(parentToken, childToken string) error {
	p.Lock()
	defer p.Unlock()

	// Get existing linked from list
	lf, err := p.cachedLinkedFromLocked(parentToken)
	if err != nil {
		return fmt.Errorf("cachedLinkedFromLocked %v: %v", parentToken, err)
	}

	// Update list
	delete(lf.Tokens, childToken)

	// Save list
	b, err := json.Marshal(lf)
	if err != nil {
		return err
	}
	fp := p.cachedLinkedFromPath(parentToken)
	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return fmt.Errorf("WriteFile: %v", err)
	}

	return nil
}

func (p *piPlugin) hookNewRecordPre(payload string) error {
	nr, err := tlogbe.DecodeNewRecord([]byte(payload))
	if err != nil {
		return err
	}

	// TODO verify ProposalMetadata signature. This is already done in
	// www but we should do it here anyway since its plugin data.

	// Decode ProposalMetadata
	var pm *pi.ProposalMetadata
	for _, v := range nr.Files {
		if v.Name == pi.FileNameProposalMetadata {
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
		return fmt.Errorf("proposal metadata not found")
	}

	// Verify the linkto is an RFP and that the RFP is eligible to be
	// linked to. We currently only allow linking to RFP proposals that
	// have been approved by a ticket vote.
	if pm.LinkTo != "" {
		if isRFP(*pm) {
			return pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPropLinkToInvalid,
				ErrorContext: []string{"an rfp cannot have linkto set"},
			}
		}
		tokenb, err := hex.DecodeString(pm.LinkTo)
		if err != nil {
			return pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPropLinkToInvalid,
				ErrorContext: []string{"invalid hex"},
			}
		}
		r, err := p.backend.GetVetted(tokenb, "")
		if err != nil {
			if err == backend.ErrRecordNotFound {
				return pi.UserErrorReply{
					ErrorCode:    pi.ErrorStatusPropLinkToInvalid,
					ErrorContext: []string{"proposal not found"},
				}
			}
			return err
		}
		linkToPM, err := proposalMetadataFromFiles(r.Files)
		if err != nil {
			return err
		}
		if linkToPM == nil {
			return pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPropLinkToInvalid,
				ErrorContext: []string{"proposal not an rfp"},
			}
		}
		if !isRFP(*linkToPM) {
			return pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPropLinkToInvalid,
				ErrorContext: []string{"proposal not an rfp"},
			}
		}
		if time.Now().Unix() > linkToPM.LinkBy {
			// Link by deadline has expired. New links are not allowed.
			return pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPropLinkToInvalid,
				ErrorContext: []string{"rfp link by deadline expired"},
			}
		}
		s := ticketvote.Summaries{
			Tokens: []string{pm.LinkTo},
		}
		b, err := ticketvote.EncodeSummaries(s)
		if err != nil {
			return err
		}
		reply, err := p.backend.Plugin(ticketvote.ID,
			ticketvote.CmdSummaries, string(b))
		if err != nil {
			return fmt.Errorf("Plugin %v %v: %v",
				ticketvote.ID, ticketvote.CmdSummaries, err)
		}
		sr, err := ticketvote.DecodeSummariesReply([]byte(reply))
		if err != nil {
			return err
		}
		summary, ok := sr.Summaries[pm.LinkTo]
		if !ok {
			return fmt.Errorf("summary not found %v", pm.LinkTo)
		}
		if !summary.Approved {
			return pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPropLinkToInvalid,
				ErrorContext: []string{"rfp vote not approved"},
			}
		}
	}

	return nil
}

func convertPropStatusFromMDStatus(s backend.MDStatusT) pi.PropStatusT {
	var status pi.PropStatusT
	switch s {
	case backend.MDStatusUnvetted, backend.MDStatusIterationUnvetted:
		status = pi.PropStatusUnvetted
	case backend.MDStatusVetted:
		status = pi.PropStatusPublic
	case backend.MDStatusCensored:
		status = pi.PropStatusCensored
	case backend.MDStatusArchived:
		status = pi.PropStatusAbandoned
	}
	return status
}

func (p *piPlugin) hookEditRecordPre(payload string) error {
	er, err := tlogbe.DecodeEditRecord([]byte(payload))
	if err != nil {
		return err
	}

	// TODO verify files were changed. Before adding this, verify that
	// politeiad will also error if no files were changed.

	// Verify proposal status
	status := convertPropStatusFromMDStatus(er.Current.RecordMetadata.Status)
	if status != pi.PropStatusUnvetted && status != pi.PropStatusPublic {
		return pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusPropStatusInvalid,
		}
	}

	// Verify vote status
	token := er.RecordMetadata.Token
	s := ticketvote.Summaries{
		Tokens: []string{token},
	}
	b, err := ticketvote.EncodeSummaries(s)
	if err != nil {
		return err
	}
	reply, err := p.backend.Plugin(ticketvote.ID,
		ticketvote.CmdSummaries, string(b))
	if err != nil {
		return fmt.Errorf("ticketvote Summaries: %v", err)
	}
	sr, err := ticketvote.DecodeSummariesReply([]byte(reply))
	if err != nil {
		return err
	}
	summary, ok := sr.Summaries[token]
	if !ok {
		return fmt.Errorf("ticketvote summmary not found")
	}
	if summary.Status != ticketvote.VoteStatusUnauthorized {
		e := fmt.Sprintf("vote status got %v, want %v",
			ticketvote.VoteStatus[summary.Status],
			ticketvote.VoteStatus[ticketvote.VoteStatusUnauthorized])
		return pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusVoteStatusInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify that the linkto has not changed. This only applies to
	// public proposal. Unvetted proposals are allowed to change their
	// linkto.
	if status == pi.PropStatusPublic {
		pmCurr, err := proposalMetadataFromFiles(er.Current.Files)
		if err != nil {
			return err
		}
		pmNew, err := proposalMetadataFromFiles(er.FilesAdd)
		if err != nil {
			return err
		}
		if pmCurr.LinkTo != pmNew.LinkTo {
			return pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPropLinkToInvalid,
				ErrorContext: []string{"linkto cannot change on public proposal"},
			}
		}
	}

	return nil
}

func (p *piPlugin) hookSetRecordStatusPost(payload string) error {
	srs, err := tlogbe.DecodeSetRecordStatus([]byte(payload))
	if err != nil {
		return err
	}

	// Parse the status change metadata
	var sc *pi.StatusChange
	for _, v := range srs.MDAppend {
		if v.ID != pi.MDStreamIDStatusChanges {
			continue
		}

		sc, err = pi.DecodeStatusChange([]byte(v.Payload))
		if err != nil {
			return err
		}
		break
	}
	if sc == nil {
		return fmt.Errorf("status change append metadata not found")
	}

	// Parse the existing status changes metadata stream
	var statuses []pi.StatusChange
	for _, v := range srs.Current.Metadata {
		if v.ID != pi.MDStreamIDStatusChanges {
			continue
		}

		statuses, err = pi.DecodeStatusChanges([]byte(v.Payload))
		if err != nil {
			return err
		}
		break
	}

	// Verify version is the latest version
	if sc.Version != srs.Current.Version {
		e := fmt.Sprintf("version not current: got %v, want %v",
			sc.Version, srs.Current.Version)
		return pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPropVersionInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify status change is allowed
	var from pi.PropStatusT
	if len(statuses) == 0 {
		// No previous status changes exist. Proposal is unvetted.
		from = pi.PropStatusUnvetted
	} else {
		from = statuses[len(statuses)-1].Status
	}
	_, isAllowed := pi.StatusChanges[from][sc.Status]
	if !isAllowed {
		e := fmt.Sprintf("from %v to %v status change not allowed",
			from, sc.Status)
		return pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPropStatusChangeInvalid,
			ErrorContext: []string{e},
		}
	}

	// If the LinkTo field has been set then the linkedFrom
	// list might need to be updated for the proposal that is being
	// linked to, depending on the status change that is being made.
	pm, err := proposalMetadataFromFiles(srs.Current.Files)
	if err != nil {
		return err
	}
	if pm != nil && pm.LinkTo != "" {
		// Link from has been set. Check if the status change requires
		// the parent proposal's linked from list to be updated.
		var (
			parentToken = pm.LinkTo
			childToken  = srs.RecordMetadata.Token
		)
		switch srs.RecordMetadata.Status {
		case backend.MDStatusVetted:
			// Proposal has been made public. Add child token to parent
			// token's linked from list.
			err := p.cachedLinkedFromAdd(parentToken, childToken)
			if err != nil {
				return fmt.Errorf("cachedLinkedFromAdd: %v", err)
			}
		case backend.MDStatusCensored:
			// Proposal has been censored. Delete child token from parent
			// token's linked from list.
			err := p.cachedLinkedFromDel(parentToken, childToken)
			if err != nil {
				return fmt.Errorf("cachedLinkedFromDel: %v", err)
			}
		}
	}

	return nil
}

func (p *piPlugin) Setup() error {
	log.Tracef("pi Setup")

	// Verify vote plugin dependency

	return nil
}

func (p *piPlugin) cmdProposals(payload string) (string, error) {
	ps, err := pi.DecodeProposals([]byte(payload))
	if err != nil {
		return "", err
	}
	_ = ps

	/*
		// TODO just because a cached linked from doesn't exist doesn't
		// mean the token isn't valid. We need to check if the token
		// corresponds to a real proposal.
		proposals := make(map[string]pi.ProposalData, len(ps.Tokens))
		for _, v := range ps.Tokens {
			lf, err := p.cachedLinkedFrom(v)
			if err != nil {
				if err == errRecordNotFound {
					continue
				}
				return "", fmt.Errorf("cachedLinkedFrom %v: %v", v, err)
			}
		}
	*/

	return "", nil
}

func (p *piPlugin) Cmd(cmd, payload string) (string, error) {
	log.Tracef("pi Cmd: %v %v", cmd, payload)

	switch cmd {
	case pi.CmdProposals:
		return p.cmdProposals(payload)
	}

	return "", nil
}

func (p *piPlugin) Hook(h tlogbe.HookT, payload string) error {
	log.Tracef("pi Hook: %v", tlogbe.Hooks[h])

	switch h {
	case tlogbe.HookNewRecordPre:
		return p.hookNewRecordPre(payload)
	case tlogbe.HookEditRecordPre:
		return p.hookEditRecordPre(payload)
	case tlogbe.HookSetRecordStatusPost:
		return p.hookSetRecordStatusPost(payload)
	}

	return nil
}

func (p *piPlugin) Fsck() error {
	log.Tracef("pi Fsck")

	// linkedFrom cache

	return nil
}

func NewPiPlugin(backend *tlogbe.TlogBackend, settings []backend.PluginSetting) *piPlugin {
	// TODO these should be passed in as plugin settings
	var (
		dataDir string
	)
	return &piPlugin{
		dataDir: dataDir,
		backend: backend,
	}
}
