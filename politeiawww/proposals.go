// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/cache"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	www2 "github.com/decred/politeia/politeiawww/api/www/v2"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

const (
	mimeTypeText = "text/plain"
	mimeTypePNG  = "image/png"
)

var (
	validProposalName = regexp.MustCompile(createProposalNameRegex())
)

// proposalStats is used to provide a summary of the number of proposals
// grouped by proposal status.
type proposalsSummary struct {
	Invalid           int
	NotReviewed       int
	Censored          int
	Public            int
	UnreviewedChanges int
	Abandoned         int
}

// proposalsFilter is used to pass filtering parameters into the filterProps
// function.
type proposalsFilter struct {
	After    string
	Before   string
	UserID   string
	StateMap map[www.PropStateT]bool
}

// parseProposalName returns the proposal name given the proposal index file
// payload.
func parseProposalName(payload string) (string, error) {
	// decode payload (base64)
	rawPayload, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", err
	}
	// @rgeraldes - used reader instead of scanner
	// due to the size of the input (scanner > token too long)
	// get the first line from the payload
	reader := bufio.NewReader(bytes.NewReader(rawPayload))
	proposalName, _, err := reader.ReadLine()
	if err != nil {
		return "", err
	}

	return string(proposalName), nil
}

// isValidProposalName returns whether the provided string is a valid proposal
// name.
func isValidProposalName(str string) bool {
	return validProposalName.MatchString(str)
}

// createProposalNameRegex returns a regex string for matching the proposal
// name.
func createProposalNameRegex() string {
	var validProposalNameBuffer bytes.Buffer
	validProposalNameBuffer.WriteString("^[")

	for _, supportedChar := range www.PolicyProposalNameSupportedChars {
		if len(supportedChar) > 1 {
			validProposalNameBuffer.WriteString(supportedChar)
		} else {
			validProposalNameBuffer.WriteString(`\` + supportedChar)
		}
	}
	minNameLength := strconv.Itoa(www.PolicyMinProposalNameLength)
	maxNameLength := strconv.Itoa(www.PolicyMaxProposalNameLength)
	validProposalNameBuffer.WriteString("]{")
	validProposalNameBuffer.WriteString(minNameLength + ",")
	validProposalNameBuffer.WriteString(maxNameLength + "}$")

	return validProposalNameBuffer.String()
}

func isRFPSubmission(pr *www.ProposalRecord) bool {
	// Right now the only proposals that we allow linking to
	// are RFPs so if the linkto is set than this is an RFP
	// submission. This may change in the future, at which
	// point we'll actually have to check the linkto proposal
	// to see if its an RFP.
	return pr.LinkTo != ""
}

// tokenIsValid returns whether the provided string is a valid politeiad
// censorship record token.
func tokenIsValid(token string) bool {
	b, err := hex.DecodeString(token)
	if err != nil {
		return false
	}
	if len(b) != pd.TokenSize {
		return false
	}
	return true
}

func getInvalidTokens(tokens []string) []string {
	invalidTokens := make([]string, 0, len(tokens))

	for _, token := range tokens {
		if !tokenIsValid(token) {
			invalidTokens = append(invalidTokens, token)
		}
	}

	return invalidTokens
}

// validateVoteBit ensures that bit is a valid vote bit.
func validateVoteBit(vote www2.Vote, bit uint64) error {
	if len(vote.Options) == 0 {
		return fmt.Errorf("vote corrupt")
	}
	if bit == 0 {
		return fmt.Errorf("invalid bit 0x%x", bit)
	}
	if vote.Mask&bit != bit {
		return fmt.Errorf("invalid mask 0x%x bit 0x%x",
			vote.Mask, bit)
	}

	for _, v := range vote.Options {
		if v.Bits == bit {
			return nil
		}
	}

	return fmt.Errorf("bit not found 0x%x", bit)
}

var (
	errDataFileNotFound = errors.New("proposal data json file not found")
)

func (p *politeiawww) validateProposalData(pd www.ProposalData) error {
	// Validate LinkTo
	if pd.LinkTo != "" {
		if !tokenIsValid(pd.LinkTo) {
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"invalid token"},
			}
		}

		// Validate the LinkTo proposal. The only type of proposal
		// that we currently allow linking to is an RFP.
		r, err := p.cache.Record(pd.LinkTo)
		if err != nil {
			if err == cache.ErrRecordNotFound {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvalidLinkTo,
				}
			}
		}
		pr := convertPropFromCache(*r)
		switch {
		case !pr.IsRFP():
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"linkto proposal is not an rfp"},
			}
		case time.Now().Unix() > pr.LinkBy:
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"linkto proposal deadline is expired"},
			}
		case pr.State != www.PropStateVetted:
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"linkto proposal is not vetted"},
			}
		case pr.IsRFP() && pd.LinkBy != 0:
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"an rfp cannot link to an rfp"},
			}
		}
	}

	// Validate LinkBy
	if pd.LinkBy != 0 {
		ts := time.Now().Unix() + www.PolicyMinLinkByPeriod
		if pd.LinkBy < ts {
			e := fmt.Sprintf("linkby period cannot be shorter than %v seconds",
				www.PolicyMinLinkByPeriod)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkBy,
				ErrorContext: []string{e},
			}
		}
	}

	return nil
}

// validateProposal ensures that the given new proposal meets the api policy
// requirements. If a proposal data file exists (currently optional) then it is
// parsed and a ProposalData is returned.
func (p *politeiawww) validateProposal(np www.NewProposal, u *user.User) (*www.ProposalData, error) {
	if len(np.Files) == 0 {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusProposalMissingFiles,
			ErrorContext: []string{"no files found"},
		}
	}

	// Verify the files adhere to all policy requirements
	var (
		countTextFiles  int
		countImageFiles int
		foundIndexFile  bool
		foundDataFile   bool
		proposalData    *www.ProposalData
	)
	filenames := make(map[string]struct{}, len(np.Files))
	digests := make([]*[sha256.Size]byte, 0, len(np.Files))
	for _, v := range np.Files {
		// Validate file name
		_, ok := filenames[v.Name]
		if ok {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusProposalDuplicateFilenames,
				ErrorContext: []string{v.Name},
			}
		}
		filenames[v.Name] = struct{}{}

		// Validate file payload
		if v.Payload == "" {
			e := fmt.Sprintf("base64 payload is empty for file '%v'",
				v.Name)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidBase64,
				ErrorContext: []string{e},
			}
		}
		payloadb, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidBase64,
				ErrorContext: []string{v.Name},
			}
		}

		// Verify computed file digest matches given file digest
		digest := util.Digest(payloadb)
		d, ok := util.ConvertDigest(v.Digest)
		if !ok {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{v.Name},
			}
		}
		if !bytes.Equal(digest, d[:]) {
			e := fmt.Sprintf("computed digest does not match given digest "+
				"for file '%v'", v.Name)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{e},
			}
		}

		// Aggregate file digests for merkle root calc
		digests = append(digests, &d)

		// Verify detected MIME type matches given mime type
		ct := http.DetectContentType(payloadb)
		mimePayload, _, err := mime.ParseMediaType(ct)
		if err != nil {
			return nil, err
		}
		mimeFile, _, err := mime.ParseMediaType(v.MIME)
		if err != nil {
			log.Debugf("validateProposal: ParseMediaType(%v): %v",
				v.MIME, err)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidMIMEType,
				ErrorContext: []string{v.Name},
			}
		}
		if mimeFile != mimePayload {
			e := fmt.Sprintf("detected mime '%v' does not match '%v' for file '%v'",
				mimePayload, mimeFile, v.Name)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidMIMEType,
				ErrorContext: []string{e},
			}
		}

		// Run MIME type specific validation
		switch mimeFile {
		case mimeTypeText:
			countTextFiles++

			// Verify text file size
			if len(payloadb) > www.PolicyMaxMDSize {
				e := fmt.Sprintf("file size %v exceeds max %v for file '%v'",
					len(payloadb), www.PolicyMaxMDSize, v.Name)
				return nil, www.UserError{
					ErrorCode:    www.ErrorStatusMaxMDSizeExceededPolicy,
					ErrorContext: []string{e},
				}
			}

			// The only text files that are allowed are the index markdown
			// file and the data json file.
			switch v.Name {
			case www.PolicyIndexFileName:
				// Index markdown file

				// Only one index file is allowed
				if foundIndexFile {
					e := fmt.Sprintf("more than one %v file found",
						www.PolicyIndexFileName)
					return nil, www.UserError{
						ErrorCode:    www.ErrorStatusMaxMDsExceededPolicy,
						ErrorContext: []string{e},
					}
				}
				foundIndexFile = true

				// Validate proposal name
				name, err := getProposalName(np.Files)
				if err != nil {
					return nil, err
				}
				if !isValidProposalName(name) {
					return nil, www.UserError{
						ErrorCode:    www.ErrorStatusProposalInvalidTitle,
						ErrorContext: []string{createProposalNameRegex()},
					}
				}

			case www.PolicyDataFileName:
				// Data json file

				// Only one data file is allowed
				if foundDataFile {
					e := fmt.Sprintf("more than one %v file found",
						www.PolicyDataFileName)
					return nil, www.UserError{
						ErrorCode:    www.ErrorStatusMaxMDsExceededPolicy,
						ErrorContext: []string{e},
					}
				}
				foundDataFile = true

				// Parse proposal data json. Unknown fields are not allowed.
				d := json.NewDecoder(strings.NewReader(string(payloadb)))
				d.DisallowUnknownFields()

				var pd www.ProposalData
				err = d.Decode(&pd)
				if err != nil {
					log.Debugf("parseProposalDataFile: decode json: %v", err)
					return nil, www.UserError{
						ErrorCode:    www.ErrorStatusInvalidProposalData,
						ErrorContext: []string{"invalid json"},
					}
				}

				err = p.validateProposalData(pd)
				if err != nil {
					return nil, err
				}

				// This value is returned
				proposalData = &pd

			default:
				return nil, www.UserError{
					ErrorCode:    www.ErrorStatusMaxMDsExceededPolicy,
					ErrorContext: []string{v.Name},
				}
			}

		case mimeTypePNG:
			countImageFiles++

			// Verify image file size
			if len(payloadb) > www.PolicyMaxImageSize {
				e := fmt.Sprintf("file size %v exceeds max %v for file '%v'",
					len(payloadb), www.PolicyMaxImageSize, v.Name)
				return nil, www.UserError{
					ErrorCode:    www.ErrorStatusMaxImageSizeExceededPolicy,
					ErrorContext: []string{e},
				}
			}

		default:
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidMIMEType,
				ErrorContext: []string{v.MIME},
			}
		}
	}

	// Verify that an index file is present. The data file is
	// currently optional.
	if !foundIndexFile {
		e := fmt.Sprintf("%v file not found", www.PolicyIndexFileName)
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusProposalMissingFiles,
			ErrorContext: []string{e},
		}
	}

	// Verify file counts are acceptable
	if countTextFiles > www.PolicyMaxMDs {
		e := fmt.Sprintf("got %v text files; max is %v",
			countTextFiles, www.PolicyMaxMDs)
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusMaxMDsExceededPolicy,
			ErrorContext: []string{e},
		}
	}
	if countImageFiles > www.PolicyMaxImages {
		e := fmt.Sprintf("got %v image files, max is %v",
			countImageFiles, www.PolicyMaxImages)
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusMaxImagesExceededPolicy,
			ErrorContext: []string{e},
		}
	}

	// Verify signature. The signature message is the merkle root
	// of the proposal files.
	sig, err := util.ConvertSignature(np.Signature)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}
	pk, err := identity.PublicIdentityFromBytes(u.ActiveIdentity().Key[:])
	if err != nil {
		return nil, err
	}
	mr := merkle.Root(digests)
	if !pk.VerifyMessage([]byte(hex.EncodeToString(mr[:])), sig) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Verify the user signed using their active identity
	if u.PublicKey() != np.PublicKey {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Verify proposal data

	return proposalData, nil
}

func voteStatusFromVoteSummary(r decredplugin.VoteSummaryReply, bestBlock uint64) www.PropVoteStatusT {
	switch {
	case !r.Authorized:
		return www.PropVoteStatusNotAuthorized
	case r.EndHeight == "":
		return www.PropVoteStatusAuthorized
	default:
		endHeight, err := strconv.ParseUint(r.EndHeight, 10, 64)
		if err != nil {
			// This should not happen
			log.Errorf("voteStatusFromVoteSummary: ParseUint "+
				"failed on '%v': %v", r.EndHeight, err)
		}

		if bestBlock < endHeight {
			return www.PropVoteStatusStarted
		}

		return www.PropVoteStatusFinished
	}
}

// getProposalName returns the proposal name based on the index markdown file.
func getProposalName(files []www.File) (string, error) {
	for _, file := range files {
		if file.Name == www.PolicyIndexFileName {
			return parseProposalName(file.Payload)
		}
	}
	return "", nil
}

// convertWWWPropCreditFromDatabasePropCredit coverts a database proposal
// credit to a v1 proposal credit.
func convertWWWPropCreditFromDatabasePropCredit(credit user.ProposalCredit) www.ProposalCredit {
	return www.ProposalCredit{
		PaywallID:     credit.PaywallID,
		Price:         credit.Price,
		DatePurchased: credit.DatePurchased,
		TxID:          credit.TxID,
	}
}

// getProp gets the most recent verions of the given proposal from the cache
// then fills in any missing fields before returning the proposal.
func (p *politeiawww) getProp(token string) (*www.ProposalRecord, error) {
	log.Tracef("getProp: %v", token)

	r, err := p.cache.Record(token)
	if err != nil {
		return nil, err
	}
	pr := convertPropFromCache(*r)

	// Find linked from proposals
	lfr, err := p.decredLinkedFrom([]string{token})
	if err != nil {
		return nil, err
	}
	linkedFrom, ok := lfr.LinkedFrom[token]
	if ok {
		pr.LinkedFrom = linkedFrom
	}

	// Find the number of comments for the proposal
	dc, err := p.decredGetComments(token)
	if err != nil {
		log.Errorf("getProp: decredGetComments failed "+
			"for token %v", token)
	}
	pr.NumComments = uint(len(dc))

	// Fill in proposal author info
	u, err := p.db.UserGetByPubKey(pr.PublicKey)
	if err != nil {
		log.Errorf("getProp: UserGetByPubKey: token:%v "+
			"pubKey:%v err:%v", token, pr.PublicKey, err)
	} else {
		pr.UserId = u.ID.String()
		pr.Username = u.Username
	}

	return &pr, nil
}

// getProps returns a [token]www.ProposalRecord map for the provided list of
// censorship tokens. If a proposal is not found, the map will not include an
// entry for the corresponding censorship token. It is the responsibility of
// the caller to ensure that results are returned for all of the provided
// censorship tokens.
func (p *politeiawww) getProps(tokens []string) (map[string]www.ProposalRecord, error) {
	log.Tracef("getProps: %v", tokens)

	// Get the proposals from the cache
	records, err := p.cache.Records(tokens, false)
	if err != nil {
		return nil, err
	}

	// Use pointers for now so the props can be easily updated
	props := make(map[string]*www.ProposalRecord, len(records))
	for _, v := range records {
		pr := convertPropFromCache(v)
		props[v.CensorshipRecord.Token] = &pr
	}

	// Get the number of comments for each proposal. Comments
	// are part of decred plugin so this must be fetched from
	// the cache separately.
	dnc, err := p.decredGetNumComments(tokens)
	if err != nil {
		return nil, err
	}
	for token, numComments := range dnc {
		props[token].NumComments = uint(numComments)
	}

	// Find linked from proposals
	lfr, err := p.decredLinkedFrom(tokens)
	if err != nil {
		return nil, err
	}
	for token, linkedFrom := range lfr.LinkedFrom {
		props[token].LinkedFrom = linkedFrom
	}

	// Compile a list of unique proposal author pubkeys. These
	// are needed to lookup the proposal author info.
	pubKeys := make(map[string]struct{})
	for _, pr := range props {
		if _, ok := pubKeys[pr.PublicKey]; !ok {
			pubKeys[pr.PublicKey] = struct{}{}
		}
	}

	// Lookup proposal authors
	pk := make([]string, 0, len(pubKeys))
	for k := range pubKeys {
		pk = append(pk, k)
	}
	users, err := p.db.UsersGetByPubKey(pk)
	if err != nil {
		return nil, err
	}
	if len(users) != len(pubKeys) {
		// A user is missing from the userdb for one
		// or more public keys. We're in trouble!
		notFound := make([]string, 0, len(pubKeys))
		for v := range pubKeys {
			if _, ok := users[v]; !ok {
				notFound = append(notFound, v)
			}
		}
		e := fmt.Sprintf("users not found for pubkeys: %v",
			strings.Join(notFound, ", "))
		panic(e)
	}

	// Fill in proposal author info
	for i, pr := range props {
		props[i].UserId = users[pr.PublicKey].ID.String()
		props[i].Username = users[pr.PublicKey].Username
	}

	// Convert pointers to values
	proposals := make(map[string]www.ProposalRecord, len(props))
	for token, pr := range props {
		proposals[token] = *pr
	}

	return proposals, nil
}

// getPropVersion gets a specific version of a proposal from the cache then
// fills in any misssing fields before returning the proposal.
func (p *politeiawww) getPropVersion(token, version string) (*www.ProposalRecord, error) {
	log.Tracef("getPropVersion: %v %v", token, version)

	r, err := p.cache.RecordVersion(token, version)
	if err != nil {
		return nil, err
	}
	pr := convertPropFromCache(*r)

	// Fetch number of comments for proposal from cache
	dc, err := p.decredGetComments(token)
	if err != nil {
		return nil, err
	}
	pr.NumComments = uint(len(dc))

	// Find linked from proposals
	lfr, err := p.decredLinkedFrom([]string{token})
	if err != nil {
		return nil, err
	}
	linkedFrom, ok := lfr.LinkedFrom[token]
	if ok {
		pr.LinkedFrom = linkedFrom
	}

	// Fill in proposal author info
	u, err := p.db.UserGetByPubKey(pr.PublicKey)
	if err != nil {
		return nil, err
	} else {
		pr.UserId = u.ID.String()
		pr.Username = u.Username
	}

	return &pr, nil
}

// getAllProps gets the latest version of all proposals from the cache then
// fills any missing fields before returning the proposals.
func (p *politeiawww) getAllProps() ([]www.ProposalRecord, error) {
	log.Tracef("getAllProps")

	// Get proposals from cache
	records, err := p.cache.Inventory()
	if err != nil {
		return nil, err
	}

	// Convert props and fill in missing info
	props := make([]www.ProposalRecord, 0, len(records))
	for _, v := range records {
		pr := convertPropFromCache(v)
		token := pr.CensorshipRecord.Token

		// Fill in num comments
		dc, err := p.decredGetComments(token)
		if err != nil {
			return nil, fmt.Errorf("decredGetComments %v: %v",
				pr.CensorshipRecord.Token, err)
		}
		pr.NumComments = uint(len(dc))

		// Find linked from proposals
		lfr, err := p.decredLinkedFrom([]string{token})
		if err != nil {
			return nil, err
		}
		linkedFrom, ok := lfr.LinkedFrom[token]
		if ok {
			pr.LinkedFrom = linkedFrom
		}

		// Fill in author info
		u, err := p.db.UserGetByPubKey(pr.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("UserGetByPubKey %v %v: %v",
				pr.CensorshipRecord.Token, pr.PublicKey, err)
		} else {
			pr.UserId = u.ID.String()
			pr.Username = u.Username
		}

		props = append(props, pr)
	}

	return props, nil
}

// filterProps filters the given proposals according to the filtering
// parameters specified by the passed in proposalsFilter.  filterProps will
// only return a single page of proposals regardless of how many proposals are
// passed in.
func filterProps(filter proposalsFilter, all []www.ProposalRecord) []www.ProposalRecord {
	log.Tracef("filterProps")

	sort.Slice(all, func(i, j int) bool {
		// Sort by older timestamp first, if timestamps are different
		// from each other
		if all[i].Timestamp != all[j].Timestamp {
			return all[i].Timestamp < all[j].Timestamp
		}

		// Otherwise sort by token
		return all[i].CensorshipRecord.Token >
			all[j].CensorshipRecord.Token
	})

	// pageStarted stores whether or not it's okay to start adding
	// proposals to the array. If the after or before parameter is
	// supplied, we must find the beginning (or end) of the page first.
	pageStarted := (filter.After == "" && filter.Before == "")
	beforeIdx := -1
	proposals := make([]www.ProposalRecord, 0, len(all))

	// Iterate in reverse order because they're sorted by oldest
	// timestamp first.
	for i := len(all) - 1; i >= 0; i-- {
		proposal := all[i]

		// Filter by user if it's provided.
		if (filter.UserID != "") && (filter.UserID != proposal.UserId) {
			continue
		}

		// Filter by the state.
		if val, ok := filter.StateMap[proposal.State]; !ok || !val {
			continue
		}

		if pageStarted {
			proposals = append(proposals, proposal)
			if len(proposals) >= www.ProposalListPageSize {
				break
			}
		} else if filter.After != "" {
			// The beginning of the page has been found, so
			// the next public proposal is added.
			pageStarted = proposal.CensorshipRecord.Token == filter.After
		} else if filter.Before != "" {
			// The end of the page has been found, so we'll
			// have to iterate in the other direction to
			// add the proposals; save the current index.
			if proposal.CensorshipRecord.Token == filter.Before {
				beforeIdx = i
				break
			}
		}
	}

	// If beforeIdx is set, the caller is asking for vetted proposals
	// whose last result is before the provided proposal.
	if beforeIdx >= 0 {
		for _, proposal := range all[beforeIdx+1:] {
			// Filter by user if it's provided.
			if (filter.UserID != "") && (filter.UserID != proposal.UserId) {
				continue
			}

			// Filter by the state.
			if val, ok := filter.StateMap[proposal.State]; !ok || !val {
				continue
			}

			// The iteration direction is oldest -> newest,
			// so proposals are prepended to the array so
			// the result will be newest -> oldest.
			proposals = append([]www.ProposalRecord{proposal},
				proposals...)
			if len(proposals) >= www.ProposalListPageSize {
				break
			}
		}
	}

	return proposals
}

// getUserProps gets the latest version of all proposals from the cache and
// then filters the proposals according to the specified proposalsFilter, which
// is required to contain a userID.  In addition to a page of filtered user
// proposals, this function also returns summary statistics for all of the
// proposals that the user has submitted grouped by proposal status.
func (p *politeiawww) getUserProps(filter proposalsFilter) ([]www.ProposalRecord, *proposalsSummary, error) {
	log.Tracef("getUserProps: %v", filter.UserID)

	if filter.UserID == "" {
		return nil, nil, fmt.Errorf("filter missing userID")
	}

	// Get the latest version of all proposals from the cache
	all, err := p.getAllProps()
	if err != nil {
		return nil, nil, fmt.Errorf("getAllProps: %v", err)
	}

	// Find proposal summary statistics for the user. This
	// includes statistics on ALL of the proposals that the user
	// has submitted. Not just the single page of proposals that
	// is going to be returned.
	var ps proposalsSummary
	for _, v := range all {
		if v.UserId != filter.UserID {
			continue
		}
		switch v.Status {
		case www.PropStatusNotReviewed:
			ps.NotReviewed++
		case www.PropStatusCensored:
			ps.Censored++
		case www.PropStatusPublic:
			ps.Public++
		case www.PropStatusUnreviewedChanges:
			ps.UnreviewedChanges++
		case www.PropStatusAbandoned:
			ps.Abandoned++
		default:
			ps.Invalid++
		}
	}

	// Filter proposals according to the proposalsFilter. Only
	// a single page of proposals will be returned.
	filtered := filterProps(filter, all)

	return filtered, &ps, nil
}

func (p *politeiawww) getPropComments(token string) ([]www.Comment, error) {
	log.Tracef("getPropComments: %v", token)

	dc, err := p.decredGetComments(token)
	if err != nil {
		return nil, fmt.Errorf("decredGetComments: %v", err)
	}

	// Convert comments and fill in author info
	comments := make([]www.Comment, 0, len(dc))
	for _, v := range dc {
		c := convertCommentFromDecred(v)
		u, err := p.db.UserGetByPubKey(c.PublicKey)
		if err != nil {
			log.Errorf("getPropComments: UserGetByPubKey: "+
				"token:%v commentID:%v pubKey:%v err:%v",
				token, c.CommentID, c.PublicKey, err)
		} else {
			c.UserID = u.ID.String()
			c.Username = u.Username
		}
		comments = append(comments, c)
	}

	// Fill in comment scores
	p.RLock()
	defer p.RUnlock()

	for i, v := range comments {
		votes, ok := p.commentVotes[v.Token+v.CommentID]
		if !ok {
			log.Errorf("getPropComments: comment votes lookup "+
				"failed: token:%v commentID:%v pubKey:%v", v.Token,
				v.CommentID, v.PublicKey)
		}
		comments[i].ResultVotes = int64(votes.up - votes.down)
		comments[i].Upvotes = votes.up
		comments[i].Downvotes = votes.down
	}

	return comments, nil
}

func (p *politeiawww) getVoteSummary(token string, bestBlock uint64) (*www.VoteSummary, error) {
	vsr, err := p.decredVoteSummary(token, bestBlock)
	if err != nil {
		return nil, err
	}
	// An end height will not exist if the vote has not been
	// started yet.
	var endHeight uint64
	if vsr.EndHeight != "" {
		i, err := strconv.ParseUint(vsr.EndHeight, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse end height "+
				"'%v' for %v: %v", vsr.EndHeight, token, err)
		}
		endHeight = i
	}
	return &www.VoteSummary{
		Status:           voteStatusFromVoteSummary(*vsr, bestBlock),
		EligibleTickets:  uint32(vsr.EligibleTicketCount),
		Duration:         vsr.Duration,
		EndHeight:        endHeight,
		QuorumPercentage: vsr.QuorumPercentage,
		PassPercentage:   vsr.PassPercentage,
		Results:          convertVoteOptionResultsFromDecred(vsr.Results),
	}, nil
}

// processNewProposal tries to submit a new proposal to politeiad.
func (p *politeiawww) processNewProposal(np www.NewProposal, user *user.User) (*www.NewProposalReply, error) {
	log.Tracef("processNewProposal")

	// Pay up sucker!
	if !p.HasUserPaid(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	if !p.UserHasProposalCredits(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoProposalCredits,
		}
	}

	// Validate proposal
	proposalData, err := p.validateProposal(np, user)
	if err != nil {
		return nil, err
	}
	if proposalData == nil {
		// A proposal data file is currently optional so make
		// sure we have valid values if one was not found.
		proposalData = &www.ProposalData{}
	}

	// Assemble metadata record
	name, err := getProposalName(np.Files)
	if err != nil {
		return nil, err
	}
	md, err := mdstream.EncodeProposalGeneral(mdstream.ProposalGeneral{
		Version:   mdstream.VersionProposalGeneral,
		Timestamp: time.Now().Unix(),
		Name:      name,
		LinkBy:    proposalData.LinkBy,
		LinkTo:    proposalData.LinkTo,
		PublicKey: np.PublicKey,
		Signature: np.Signature,
	})
	if err != nil {
		return nil, err
	}

	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	n := pd.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata: []pd.MetadataStream{{
			ID:      mdstream.IDProposalGeneral,
			Payload: string(md),
		}},
		Files: convertPropFilesFromWWW(np.Files),
	}

	// Send politeiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.NewRecordRoute, n)
	if err != nil {
		return nil, err
	}

	log.Infof("Submitted proposal name: %v", name)
	for k, f := range n.Files {
		log.Infof("%02v: %v %v", k, f.Name, f.Digest)
	}

	// Handle response
	var pdReply pd.NewRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal NewProposalReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	cr := convertPropCensorFromPD(pdReply.CensorshipRecord)

	// Deduct proposal credit from user account
	err = p.SpendProposalCredit(user, cr.Token)
	if err != nil {
		return nil, err
	}

	// Fire off new proposal event
	p.fireEvent(EventTypeProposalSubmitted,
		EventDataProposalSubmitted{
			CensorshipRecord: &cr,
			ProposalName:     name,
			User:             user,
		},
	)

	return &www.NewProposalReply{
		CensorshipRecord: cr,
	}, nil
}

// processProposalDetails fetches a specific proposal version from the records
// cache and returns it.
func (p *politeiawww) processProposalDetails(propDetails www.ProposalsDetails, user *user.User) (*www.ProposalDetailsReply, error) {
	log.Tracef("processProposalDetails")

	// Version is an optional query param. Fetch latest version
	// when query param is not specified.
	var prop *www.ProposalRecord
	var err error
	if propDetails.Version == "" {
		prop, err = p.getProp(propDetails.Token)
	} else {
		prop, err = p.getPropVersion(propDetails.Token, propDetails.Version)
	}
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Setup reply
	reply := www.ProposalDetailsReply{
		Proposal: *prop,
	}

	// Vetted proposals are viewable by everyone. The contents of
	// an unvetted proposal is only viewable by admins and the
	// proposal author. Unvetted proposal metadata is viewable by
	// everyone.
	if prop.State == www.PropStateUnvetted {
		var isAuthor bool
		var isAdmin bool
		// This is a public route so a user may not exist
		if user != nil {
			isAdmin = user.Admin
			isAuthor = (prop.UserId == user.ID.String())
		}

		// Strip the non-public proposal contents if user is
		// not the author or an admin
		if !isAuthor && !isAdmin {
			reply.Proposal.Name = ""
			reply.Proposal.Files = make([]www.File, 0)
		}
	}

	return &reply, nil
}

// cacheVoteSumamary stores a given VoteSummary in memory.  This is to only
// be used for proposals whose voting period has ended so that we don't have
// to worry about cache invalidation issues.
//
// This function must be called without the lock held.
func (p *politeiawww) cacheVoteSummary(token string, voteSummary www.VoteSummary) {
	p.Lock()
	defer p.Unlock()

	p.voteSummaries[token] = voteSummary
}

// getVoteSummaries fetches the voting summary information for a set of
// proposals.
func (p *politeiawww) getVoteSummaries(tokens []string, bestBlock uint64) (map[string]www.VoteSummary, error) {
	voteSummaries := make(map[string]www.VoteSummary)
	tokensToLookup := make([]string, 0, len(tokens))

	p.RLock()
	for _, token := range tokens {
		vs, ok := p.voteSummaries[token]
		if ok {
			voteSummaries[token] = vs
		} else {
			tokensToLookup = append(tokensToLookup, token)
		}
	}
	p.RUnlock()

	if len(tokensToLookup) == 0 {
		return voteSummaries, nil
	}

	r, err := p.decredBatchVoteSummary(tokensToLookup, bestBlock)
	if err != nil {
		return nil, err
	}

	for token, summary := range r.Summaries {
		results := convertVoteOptionResultsFromDecred(summary.Results)

		// An endHeight will not exist if the proposal has not gone
		// up for vote yet.
		var endHeight uint64
		if summary.EndHeight != "" {
			i, err := strconv.ParseUint(summary.EndHeight, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse end height "+
					"'%v' for %v: %v", summary.EndHeight, token, err)
			}
			endHeight = i
		}

		vs := www.VoteSummary{
			Status:           voteStatusFromVoteSummary(summary, bestBlock),
			EligibleTickets:  uint32(summary.EligibleTicketCount),
			Duration:         summary.Duration,
			EndHeight:        endHeight,
			QuorumPercentage: summary.QuorumPercentage,
			PassPercentage:   summary.PassPercentage,
			Results:          results,
		}

		voteSummaries[token] = vs

		// If the voting period has ended the vote status
		// is not going to change so add it to the memory
		// cache.
		if vs.Status == www.PropVoteStatusFinished {
			p.cacheVoteSummary(token, vs)
		}
	}

	return voteSummaries, nil
}

// processBatchVoteSummary returns the vote summaries for the provided list
// of proposals.
func (p *politeiawww) processBatchVoteSummary(batchVoteSummary www.BatchVoteSummary) (*www.BatchVoteSummaryReply, error) {
	log.Tracef("processBatchVoteSummary")

	if len(batchVoteSummary.Tokens) > www.ProposalListPageSize {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusMaxProposalsExceededPolicy,
		}
	}

	invalidTokens := getInvalidTokens(batchVoteSummary.Tokens)
	if len(invalidTokens) > 0 {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
			ErrorContext: invalidTokens,
		}
	}

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}

	summaries, err := p.getVoteSummaries(batchVoteSummary.Tokens, bb)
	if err != nil {
		return nil, err
	}

	if len(summaries) != len(batchVoteSummary.Tokens) {
		tokensNotFound := make([]string, 0,
			len(batchVoteSummary.Tokens)-len(summaries))

		for _, token := range batchVoteSummary.Tokens {
			if _, exists := summaries[token]; !exists {
				tokensNotFound = append(tokensNotFound, token)
			}
		}

		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusProposalNotFound,
			ErrorContext: tokensNotFound,
		}
	}

	return &www.BatchVoteSummaryReply{
		BestBlock: bb,
		Summaries: summaries,
	}, nil
}

// processBatchProposals fetches a list of proposals from the records cache
// and returns them. The returned proposals do not include the proposal files.
func (p *politeiawww) processBatchProposals(bp www.BatchProposals, user *user.User) (*www.BatchProposalsReply, error) {
	log.Tracef("processBatchProposals")

	// Validate censorship tokens
	if len(bp.Tokens) > www.ProposalListPageSize {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusMaxProposalsExceededPolicy,
		}
	}
	for _, v := range bp.Tokens {
		if !tokenIsValid(v) {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
				ErrorContext: []string{v},
			}
		}
	}

	// Lookup proposals
	props, err := p.getProps(bp.Tokens)
	if err != nil {
		return nil, err
	}
	if len(props) != len(bp.Tokens) {
		// A proposal was not found for one or more of the
		// provided tokens. Figure out which ones they were.
		notFound := make([]string, 0, len(bp.Tokens))
		for _, v := range bp.Tokens {
			if _, ok := props[v]; !ok {
				notFound = append(notFound, v)
			}
		}
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusProposalNotFound,
			ErrorContext: notFound,
		}
	}

	for token, pr := range props {
		// Vetted proposals are viewable by everyone. The contents of
		// an unvetted proposal is only viewable by admins and the
		// proposal author. Unvetted proposal metadata is viewable by
		// everyone.
		if pr.State == www.PropStateUnvetted {
			var isAuthor bool
			var isAdmin bool
			// This is a public route so a user may not exist
			if user != nil {
				isAdmin = user.Admin
				isAuthor = (pr.UserId == user.ID.String())
			}

			// Strip the non-public proposal contents if user is
			// not the author or an admin. The files are already
			// not included in this request.
			if !isAuthor && !isAdmin {
				prop := props[token]
				prop.Name = ""
				props[token] = prop
			}
		}
	}

	// Convert proposals map to a slice
	proposals := make([]www.ProposalRecord, 0, len(props))
	for _, v := range props {
		proposals = append(proposals, v)
	}

	return &www.BatchProposalsReply{
		Proposals: proposals,
	}, nil
}

// verifyStatusChange verifies that the proposal status change is a valid
// status transition.  This only applies to manual status transitions that are
// initiated by an admin.  It does not apply to status changes that are caused
// by editing a proposal.
func verifyStatusChange(current, next www.PropStatusT) error {
	var err error
	switch {
	case current == www.PropStatusNotReviewed &&
		(next == www.PropStatusCensored ||
			next == www.PropStatusPublic):
	// allowed; continue
	case current == www.PropStatusUnreviewedChanges &&
		(next == www.PropStatusCensored ||
			next == www.PropStatusPublic):
		// allowed; continue
	case current == www.PropStatusPublic &&
		next == www.PropStatusAbandoned:
		// allowed; continue
	default:
		err = www.UserError{
			ErrorCode: www.ErrorStatusInvalidPropStatusTransition,
		}
	}
	return err
}

// processSetProposalStatus changes the status of an existing proposal.
func (p *politeiawww) processSetProposalStatus(sps www.SetProposalStatus, u *user.User) (*www.SetProposalStatusReply, error) {
	log.Tracef("processSetProposalStatus %v", sps.Token)

	// Ensure the status change message is not blank if the
	// proposal is being censored or abandoned.
	if sps.StatusChangeMessage == "" &&
		(sps.ProposalStatus == www.PropStatusCensored ||
			sps.ProposalStatus == www.PropStatusAbandoned) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusChangeMessageCannotBeBlank,
		}
	}

	// Ensure the provided public key is the user's active key.
	if sps.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := sps.Token + strconv.Itoa(int(sps.ProposalStatus)) +
		sps.StatusChangeMessage
	err := validateSignature(sps.PublicKey, sps.Signature, msg)
	if err != nil {
		return nil, err
	}

	// Get proposal from cache
	pr, err := p.getProp(sps.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// The only time admins are allowed to change the status of
	// their own proposals is on testnet
	if !p.cfg.TestNet {
		author, err := p.db.UserGetByPubKey(pr.PublicKey)
		if err != nil {
			return nil, err
		}
		if author.ID.String() == u.ID.String() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusReviewerAdminEqualsAuthor,
			}
		}
	}

	// Create change record
	newStatus := convertPropStatusFromWWW(sps.ProposalStatus)
	blob, err := mdstream.EncodeRecordStatusChangeV2(
		mdstream.RecordStatusChangeV2{
			Version:             mdstream.VersionRecordStatusChange,
			Timestamp:           time.Now().Unix(),
			NewStatus:           newStatus,
			Signature:           sps.Signature,
			AdminPubKey:         u.PublicKey(),
			StatusChangeMessage: sps.StatusChangeMessage,
		})
	if err != nil {
		return nil, err
	}

	// Create challenge
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	// Ensure status change is allowed
	err = verifyStatusChange(pr.Status, sps.ProposalStatus)
	if err != nil {
		return nil, err
	}

	var challengeResponse string
	switch {
	case pr.State == www.PropStateUnvetted:
		// Unvetted status change

		// Setup request
		sus := pd.SetUnvettedStatus{
			Token:     sps.Token,
			Status:    newStatus,
			Challenge: hex.EncodeToString(challenge),
			MDAppend: []pd.MetadataStream{
				{
					ID:      mdstream.IDRecordStatusChange,
					Payload: string(blob),
				},
			},
		}

		// Send unvetted status change request
		responseBody, err := p.makeRequest(http.MethodPost,
			pd.SetUnvettedStatusRoute, sus)
		if err != nil {
			return nil, err
		}

		var susr pd.SetUnvettedStatusReply
		err = json.Unmarshal(responseBody, &susr)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal "+
				"SetUnvettedStatusReply: %v", err)
		}
		challengeResponse = susr.Response

	case pr.State == www.PropStateVetted:
		// Vetted status change

		// Ensure voting has not been started or authorized yet
		bb, err := p.getBestBlock()
		if err != nil {
			return nil, fmt.Errorf("getBestBlock: %v", err)
		}
		vsr, err := p.decredVoteSummary(pr.CensorshipRecord.Token, bb)
		if err != nil {
			return nil, err
		}
		switch {
		case vsr.EndHeight != "":
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusWrongVoteStatus,
				ErrorContext: []string{"vote has started"},
			}
		case vsr.Authorized:
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusWrongVoteStatus,
				ErrorContext: []string{"vote has been authorized"},
			}
		}

		// Setup request
		svs := pd.SetVettedStatus{
			Token:     sps.Token,
			Status:    newStatus,
			Challenge: hex.EncodeToString(challenge),
			MDAppend: []pd.MetadataStream{
				{
					ID:      mdstream.IDRecordStatusChange,
					Payload: string(blob),
				},
			},
		}

		// Send vetted status change request
		responseBody, err := p.makeRequest(http.MethodPost,
			pd.SetVettedStatusRoute, svs)
		if err != nil {
			return nil, err
		}

		var svsr pd.SetVettedStatusReply
		err = json.Unmarshal(responseBody, &svsr)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal "+
				"SetVettedStatusReply: %v", err)
		}
		challengeResponse = svsr.Response

	default:
		panic(fmt.Sprintf("invalid proposal state %v %v",
			pr.CensorshipRecord.Token, pr.State))
	}

	// Verify the challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge,
		challengeResponse)
	if err != nil {
		return nil, err
	}

	// Get record from the cache
	updatedProp, err := p.getPropVersion(pr.CensorshipRecord.Token, pr.Version)
	if err != nil {
		return nil, err
	}

	// Fire off proposal status change event
	p.fireEvent(EventTypeProposalStatusChange,
		EventDataProposalStatusChange{
			Proposal:          updatedProp,
			AdminUser:         u,
			SetProposalStatus: &sps,
		},
	)

	return &www.SetProposalStatusReply{
		Proposal: *updatedProp,
	}, nil
}

// processEditProposal attempts to edit a proposal on politeiad.
func (p *politeiawww) processEditProposal(ep www.EditProposal, u *user.User) (*www.EditProposalReply, error) {
	log.Tracef("processEditProposal %v", ep.Token)

	// Validate proposal status
	cachedProp, err := p.getProp(ep.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	if cachedProp.Status == www.PropStatusCensored ||
		cachedProp.Status == www.PropStatusAbandoned {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Ensure user is the proposal author
	if cachedProp.UserId != u.ID.String() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotAuthor,
		}
	}

	// Validate proposal vote status
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	vsr, err := p.decredVoteSummary(ep.Token, bb)
	if err != nil {
		return nil, err
	}
	s := voteStatusFromVoteSummary(*vsr, bb)
	if s != www.PropVoteStatusNotAuthorized {
		e := fmt.Sprintf("got vote status %v, want %v",
			s, www.PropVoteStatusNotAuthorized)
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{e},
		}
	}

	// Validate proposal. Convert it to www.NewProposal so that
	// we can reuse the function validateProposal.
	np := www.NewProposal{
		Files:     ep.Files,
		PublicKey: ep.PublicKey,
		Signature: ep.Signature,
	}
	proposalData, err := p.validateProposal(np, u)
	if err != nil {
		return nil, err
	}
	if proposalData == nil {
		// A proposal data file is currently optional so make
		// sure we have valid values if one was not found.
		proposalData = &www.ProposalData{}
	}

	if cachedProp.State == www.PropStateVetted &&
		cachedProp.LinkTo != proposalData.LinkTo {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidLinkTo,
			ErrorContext: []string{"linkto cannot change once public"},
		}
	}

	// Assemble metadata record
	name, err := getProposalName(ep.Files)
	if err != nil {
		return nil, err
	}

	backendMetadata := mdstream.ProposalGeneral{
		Version:   mdstream.VersionProposalGeneral,
		Timestamp: time.Now().Unix(),
		Name:      name,
		LinkBy:    proposalData.LinkBy,
		LinkTo:    proposalData.LinkTo,
		PublicKey: ep.PublicKey,
		Signature: ep.Signature,
	}
	md, err := mdstream.EncodeProposalGeneral(backendMetadata)
	if err != nil {
		return nil, err
	}

	mds := []pd.MetadataStream{{
		ID:      mdstream.IDProposalGeneral,
		Payload: string(md),
	}}

	// Check if any files need to be deleted
	var delFiles []string
	for _, v := range cachedProp.Files {
		found := false
		for _, c := range ep.Files {
			if v.Name == c.Name {
				found = true
			}
		}
		if !found {
			delFiles = append(delFiles, v.Name)
		}
	}

	// Check for changes in the index.md file
	var newMDFile www.File
	for _, v := range ep.Files {
		if v.Name == www.PolicyIndexFileName {
			newMDFile = v
		}
	}

	var oldMDFile www.File
	for _, v := range cachedProp.Files {
		if v.Name == www.PolicyIndexFileName {
			oldMDFile = v
		}
	}

	mdChanges := newMDFile.Payload != oldMDFile.Payload

	// Check that the proposal has been changed
	if !mdChanges && len(delFiles) == 0 &&
		len(cachedProp.Files) == len(ep.Files) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoProposalChanges,
		}
	}

	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	e := pd.UpdateRecord{
		Token:       ep.Token,
		Challenge:   hex.EncodeToString(challenge),
		MDOverwrite: mds,
		FilesAdd:    convertPropFilesFromWWW(ep.Files),
		FilesDel:    delFiles,
	}

	var pdRoute string
	switch cachedProp.Status {
	case www.PropStatusNotReviewed, www.PropStatusUnreviewedChanges:
		pdRoute = pd.UpdateUnvettedRoute
	case www.PropStatusPublic:
		pdRoute = pd.UpdateVettedRoute
	default:
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Send politeiad request
	responseBody, err := p.makeRequest(http.MethodPost, pdRoute, e)
	if err != nil {
		return nil, err
	}

	// Handle response
	var pdReply pd.UpdateRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal UpdateUnvettedReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	// Get proposal from the cache
	updatedProp, err := p.getProp(ep.Token)
	if err != nil {
		return nil, err
	}

	// Fire off edit proposal event
	p.fireEvent(EventTypeProposalEdited,
		EventDataProposalEdited{
			Proposal: updatedProp,
		},
	)

	return &www.EditProposalReply{
		Proposal: *updatedProp,
	}, nil
}

// processAllVetted returns an array of vetted proposals. The maximum number
// of proposals returned is dictated by www.ProposalListPageSize.
func (p *politeiawww) processAllVetted(v www.GetAllVetted) (*www.GetAllVettedReply, error) {
	log.Tracef("processAllVetted")

	// Validate query params
	if (v.Before != "" && !tokenIsValid(v.Before)) ||
		(v.After != "" && !tokenIsValid(v.After)) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidCensorshipToken,
		}
	}

	// Fetch all proposals from the cache
	all, err := p.getAllProps()
	if err != nil {
		return nil, fmt.Errorf("getAllProps: %v", err)
	}

	// Filter for vetted proposals
	filter := proposalsFilter{
		After:  v.After,
		Before: v.Before,
		StateMap: map[www.PropStateT]bool{
			www.PropStateVetted: true,
		},
	}
	props := filterProps(filter, all)

	// Remove files from proposals
	for i, p := range props {
		p.Files = make([]www.File, 0)
		props[i] = p
	}

	return &www.GetAllVettedReply{
		Proposals: props,
	}, nil
}

// processCommentsGet returns all comments for a given proposal. If the user is
// logged in the user's last access time for the given comments will also be
// returned.
func (p *politeiawww) processCommentsGet(token string, u *user.User) (*www.GetCommentsReply, error) {
	log.Tracef("ProcessCommentGet: %v", token)

	// Fetch proposal comments from cache
	c, err := p.getPropComments(token)
	if err != nil {
		return nil, err
	}

	// Get the last time the user accessed these comments. This is
	// a public route so a user may not exist.
	var accessTime int64
	if u != nil {
		if u.ProposalCommentsAccessTimes == nil {
			u.ProposalCommentsAccessTimes = make(map[string]int64)
		}
		accessTime = u.ProposalCommentsAccessTimes[token]
		u.ProposalCommentsAccessTimes[token] = time.Now().Unix()
		err = p.db.UserUpdate(*u)
		if err != nil {
			return nil, err
		}
	}

	return &www.GetCommentsReply{
		Comments:   c,
		AccessTime: accessTime,
	}, nil
}

// setVoteStatusReply converts a VoteStatusReply to a VoteSummary and stores it
// in memory.  This is to only be used for proposals whose voting period has
// ended so that we don't have to worry about cache invalidation issues.
//
// This function must be called without the lock held.
//
// ** This fuction is to be removed when the deprecated vote status route is
// ** removed.
func (p *politeiawww) setVoteStatusReply(v www.VoteStatusReply) error {
	p.Lock()
	defer p.Unlock()

	endHeight, err := strconv.Atoi(v.EndHeight)
	if err != nil {
		return err
	}

	voteSummary := www.VoteSummary{
		Status:           v.Status,
		EligibleTickets:  uint32(v.NumOfEligibleVotes),
		EndHeight:        uint64(endHeight),
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
		Results:          v.OptionsResult,
	}

	p.voteSummaries[v.Token] = voteSummary

	return nil
}

// getVoteStatusReply retrieves the VoteSummary from the cache for a proposal
// whose voting period has ended and converts it to a VoteStatusReply.
//
// This function must be called without the lock held.
//
// ** This fuction is to be removed when the deprecated vote status route is
// ** removed.
func (p *politeiawww) getVoteStatusReply(token string) (*www.VoteStatusReply, bool) {
	p.RLock()
	vs, ok := p.voteSummaries[token]
	p.RUnlock()

	if !ok {
		return nil, false
	}

	var totalVotes uint64
	for _, or := range vs.Results {
		totalVotes += or.VotesReceived
	}

	voteStatusReply := www.VoteStatusReply{
		Token:              token,
		Status:             vs.Status,
		TotalVotes:         totalVotes,
		OptionsResult:      vs.Results,
		EndHeight:          strconv.Itoa(int(vs.EndHeight)),
		NumOfEligibleVotes: int(vs.EligibleTickets),
		QuorumPercentage:   vs.QuorumPercentage,
		PassPercentage:     vs.PassPercentage,
	}

	return &voteStatusReply, true
}

func (p *politeiawww) voteStatusReply(token string, bestBlock uint64) (*www.VoteStatusReply, error) {
	cachedVsr, ok := p.getVoteStatusReply(token)

	if ok {
		cachedVsr.BestBlock = strconv.Itoa(int(bestBlock))
		return cachedVsr, nil
	}

	// Vote status wasn't in the memory cache
	// so fetch it from the cache database.
	r, err := p.decredVoteSummary(token, bestBlock)
	if err != nil {
		return nil, err
	}

	results := convertVoteOptionResultsFromDecred(r.Results)
	var total uint64
	for _, v := range results {
		total += v.VotesReceived
	}

	voteStatusReply := www.VoteStatusReply{
		Token:              token,
		Status:             voteStatusFromVoteSummary(*r, bestBlock),
		TotalVotes:         total,
		OptionsResult:      results,
		EndHeight:          r.EndHeight,
		BestBlock:          strconv.Itoa(int(bestBlock)),
		NumOfEligibleVotes: r.EligibleTicketCount,
		QuorumPercentage:   r.QuorumPercentage,
		PassPercentage:     r.PassPercentage,
	}

	// If the voting period has ended the vote status
	// is not going to change so add it to the memory
	// cache.
	if voteStatusReply.Status == www.PropVoteStatusFinished {
		err = p.setVoteStatusReply(voteStatusReply)
		if err != nil {
			return nil, err
		}
	}

	return &voteStatusReply, nil
}

// processVoteStatus returns the vote status for a given proposal
func (p *politeiawww) processVoteStatus(token string) (*www.VoteStatusReply, error) {
	log.Tracef("ProcessProposalVotingStatus: %v", token)

	// Ensure proposal is vetted
	pr, err := p.getProp(token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	if pr.State != www.PropStateVetted {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Get best block
	bestBlock, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("bestBlock: %v", err)
	}

	// Get vote status
	vsr, err := p.voteStatusReply(token, bestBlock)
	if err != nil {
		return nil, fmt.Errorf("voteStatusReply: %v", err)
	}

	return vsr, nil
}

// processGetAllVoteStatus returns the vote status of all public proposals.
func (p *politeiawww) processGetAllVoteStatus() (*www.GetAllVoteStatusReply, error) {
	log.Tracef("processGetAllVoteStatus")

	// We need to determine best block height here in order
	// to set the voting status
	bestBlock, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("bestBlock: %v", err)
	}

	// Get all proposals from cache
	all, err := p.getAllProps()
	if err != nil {
		return nil, fmt.Errorf("getAllProps: %v", err)
	}

	// Compile votes statuses
	vrr := make([]www.VoteStatusReply, 0, len(all))
	for _, v := range all {
		// We only need public proposals
		if v.Status != www.PropStatusPublic {
			continue
		}

		// Get vote status for proposal
		vs, err := p.voteStatusReply(v.CensorshipRecord.Token, bestBlock)
		if err != nil {
			return nil, fmt.Errorf("voteStatusReply: %v", err)
		}

		vrr = append(vrr, *vs)
	}

	return &www.GetAllVoteStatusReply{
		VotesStatus: vrr,
	}, nil
}

func (p *politeiawww) processActiveVote() (*www.ActiveVoteReply, error) {
	log.Tracef("processActiveVote")

	// Fetch proposals that are actively being voted on
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	tir, err := p.decredTokenInventory(bb, false)
	if err != nil {
		return nil, err
	}
	props, err := p.getProps(tir.Active)
	if err != nil {
		return nil, err
	}

	// Compile proposal vote tuples
	pvt := make([]www.ProposalVoteTuple, 0, len(props))
	for _, v := range props {
		// Get vote details from cache
		vdr, err := p.decredVoteDetails(v.CensorshipRecord.Token)
		if err != nil {
			return nil, fmt.Errorf("decredVoteDetails %v: %v",
				v.CensorshipRecord.Token, err)
		}

		// Handle StartVote versioning
		var sv www.StartVote
		switch vdr.StartVote.Version {
		case decredplugin.VersionStartVoteV1:
			b := []byte(vdr.StartVote.Payload)
			dsv, err := decredplugin.DecodeStartVoteV1(b)
			if err != nil {
				return nil, fmt.Errorf("decode StartVoteV1 %v: %v",
					v.CensorshipRecord.Token, err)
			}
			sv = convertStartVoteV1FromDecred(*dsv)

		case decredplugin.VersionStartVoteV2:
			b := []byte(vdr.StartVote.Payload)
			dsv2, err := decredplugin.DecodeStartVoteV2(b)
			if err != nil {
				return nil, fmt.Errorf("decode StartVoteV2 %v: %v",
					v.CensorshipRecord.Token, err)
			}
			sv2 := convertStartVoteV2FromDecred(*dsv2)
			// Convert StartVote v2 to v1 since this route returns
			// a v1 StartVote.
			sv = convertStartVoteV2ToV1(sv2)

		default:
			return nil, fmt.Errorf("invalid StartVote version %v %v",
				v.CensorshipRecord.Token, vdr.StartVote.Version)
		}

		// Create vote tuple
		pvt = append(pvt, www.ProposalVoteTuple{
			Proposal:       v,
			StartVote:      sv,
			StartVoteReply: convertStartVoteReplyFromDecred(vdr.StartVoteReply),
		})
	}

	return &www.ActiveVoteReply{
		Votes: pvt,
	}, nil
}

// processVoteResults returns the vote details for a specific proposal and all
// of the votes that have been cast.
func (p *politeiawww) processVoteResults(token string) (*www.VoteResultsReply, error) {
	log.Tracef("processVoteResults: %v", token)

	// Ensure proposal is vetted
	pr, err := p.getProp(token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	if pr.State != www.PropStateVetted {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Get vote details from cache
	vdr, err := p.decredVoteDetails(token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}
	if vdr.StartVoteReply.StartBlockHash == "" {
		// Vote has not been started yet. No need to continue.
		return &www.VoteResultsReply{}, nil
	}

	// Get cast votes from cache
	vrr, err := p.decredProposalVotes(token)
	if err != nil {
		return nil, fmt.Errorf("decredProposalVotes: %v", err)
	}

	// Handle StartVote versioning
	var sv www.StartVote
	switch vdr.StartVote.Version {
	case decredplugin.VersionStartVoteV1:
		b := []byte(vdr.StartVote.Payload)
		dsv1, err := decredplugin.DecodeStartVoteV1(b)
		if err != nil {
			return nil, err
		}
		sv = convertStartVoteV1FromDecred(*dsv1)
	case decredplugin.VersionStartVoteV2:
		b := []byte(vdr.StartVote.Payload)
		dsv2, err := decredplugin.DecodeStartVoteV2(b)
		if err != nil {
			return nil, err
		}
		sv2 := convertStartVoteV2FromDecred(*dsv2)
		// Convert StartVote v2 to v1 since this route returns
		// a v1 StartVote.
		sv = convertStartVoteV2ToV1(sv2)
	default:
		return nil, fmt.Errorf("invalid StartVote version %v %v",
			token, vdr.StartVote.Version)
	}

	return &www.VoteResultsReply{
		StartVote:      sv,
		StartVoteReply: convertStartVoteReplyFromDecred(vdr.StartVoteReply),
		CastVotes:      convertCastVotesFromDecred(vrr.CastVotes),
	}, nil
}

// processCastVotes handles the www.Ballot call
func (p *politeiawww) processCastVotes(ballot *www.Ballot) (*www.BallotReply, error) {
	log.Tracef("processCastVotes")

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	payload, err := decredplugin.EncodeBallot(convertBallotFromWWW(*ballot))
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdBallot,
		CommandID: decredplugin.CmdBallot,
		Payload:   string(payload),
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	// Decode plugin reply
	br, err := decredplugin.DecodeBallotReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	brr := convertBallotReplyFromDecredPlugin(*br)
	return &brr, nil
}

// processProposalPaywallDetails returns a proposal paywall that enables the
// the user to purchase proposal credits. The user can only have one paywall
// active at a time.  If no paywall currently exists, a new one is created and
// the user is added to the paywall pool.
func (p *politeiawww) processProposalPaywallDetails(u *user.User) (*www.ProposalPaywallDetailsReply, error) {
	log.Tracef("processProposalPaywallDetails")

	// Ensure paywall is enabled
	if !p.paywallIsEnabled() {
		return &www.ProposalPaywallDetailsReply{}, nil
	}

	// Proposal paywalls cannot be generated until the user has paid their
	// user registration fee.
	if !p.HasUserPaid(u) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	var pp *user.ProposalPaywall
	if p.userHasValidProposalPaywall(u) {
		// Don't create a new paywall if a valid one already exists.
		pp = p.mostRecentProposalPaywall(u)
	} else {
		// Create a new paywall.
		var err error
		pp, err = p.generateProposalPaywall(u)
		if err != nil {
			return nil, err
		}
	}

	return &www.ProposalPaywallDetailsReply{
		CreditPrice:        pp.CreditPrice,
		PaywallAddress:     pp.Address,
		PaywallTxNotBefore: pp.TxNotBefore,
	}, nil
}

// processProposalPaywallPayment checks if the user has a pending paywall
// payment and returns the payment details if one is found.
func (p *politeiawww) processProposalPaywallPayment(u *user.User) (*www.ProposalPaywallPaymentReply, error) {
	log.Tracef("processProposalPaywallPayment")

	var (
		txID          string
		txAmount      uint64
		confirmations uint64
	)

	p.RLock()
	defer p.RUnlock()

	poolMember, ok := p.userPaywallPool[u.ID]
	if ok {
		txID = poolMember.txID
		txAmount = poolMember.txAmount
		confirmations = poolMember.txConfirmations
	}

	return &www.ProposalPaywallPaymentReply{
		TxID:          txID,
		TxAmount:      txAmount,
		Confirmations: confirmations,
	}, nil
}

// processAuthorizeVote sends the authorizevote command to decred plugin to
// indicate that a proposal has been finalized and is ready to be voted on.
func (p *politeiawww) processAuthorizeVote(av www.AuthorizeVote, u *user.User) (*www.AuthorizeVoteReply, error) {
	log.Tracef("processAuthorizeVote %v", av.Token)

	// Get proposal from the cache
	pr, err := p.getProp(av.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Ensure the public key is the user's active key
	if av.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := av.Token + pr.Version + av.Action
	err = validateSignature(av.PublicKey, av.Signature, msg)
	if err != nil {
		return nil, err
	}

	// Get vote details from cache
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	vsr, err := p.decredVoteSummary(av.Token, bb)
	if err != nil {
		return nil, err
	}

	// Verify record is in the right state and that the authorize
	// vote request is valid. A vote authorization may already
	// exist. We also allow vote authorizations to be revoked.
	switch {
	case isRFPSubmission(pr):
		// Record is an RFP submission. RFP submissions must be part
		// of a runoff vote, which do not require vote authorization
		// from the submission author.
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidAuthVoteAction,
			ErrorContext: []string{"cannot authorize vote for rfp submission"},
		}
	case pr.Status != www.PropStatusPublic:
		// Record not public
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	case vsr.EndHeight != "":
		// Vote has already started
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	case av.Action != decredplugin.AuthVoteActionAuthorize &&
		av.Action != decredplugin.AuthVoteActionRevoke:
		// Invalid authorize vote action
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidAuthVoteAction,
		}
	case av.Action == decredplugin.AuthVoteActionAuthorize && vsr.Authorized:
		// Cannot authorize vote; vote has already been authorized
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteAlreadyAuthorized,
		}
	case av.Action == decredplugin.AuthVoteActionRevoke && !vsr.Authorized:
		// Cannot revoke authorization; vote has not been authorized
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteNotAuthorized,
		}
	case pr.PublicKey != av.PublicKey:
		// User is not the author. First make sure the author didn't
		// submit the proposal using an old identity.
		usr, err := p.db.UserGetByPubKey(pr.PublicKey)
		if err != nil {
			return nil, err
		}
		if u.ID.String() != usr.ID.String() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusUserNotAuthor,
			}
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, fmt.Errorf("Random: %v", err)
	}

	dav := convertAuthorizeVoteFromWWW(av)
	payload, err := decredplugin.EncodeAuthorizeVote(dav)
	if err != nil {
		return nil, fmt.Errorf("EncodeAuthorizeVote: %v", err)
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdAuthorizeVote,
		CommandID: decredplugin.CmdAuthorizeVote + " " + av.Token,
		Payload:   string(payload),
	}

	// Send authorizevote plugin request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal PluginCommandReply: %v", err)
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, fmt.Errorf("VerifyChallenge: %v", err)
	}

	// Decode plugin reply
	avr, err := decredplugin.DecodeAuthorizeVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, fmt.Errorf("DecodeAuthorizeVoteReply: %v", err)
	}

	if !p.test && avr.Action == decredplugin.AuthVoteActionAuthorize {
		p.fireEvent(EventTypeProposalVoteAuthorized,
			EventDataProposalVoteAuthorized{
				AuthorizeVote: &av,
				User:          u,
			},
		)
	}

	return &www.AuthorizeVoteReply{
		Action:  avr.Action,
		Receipt: avr.Receipt,
	}, nil
}

func verifyStartVoteV2(sv www2.StartVote, voteDurationMin, voteDurationMax uint32) error {
	// Validate vote bits
	for _, v := range sv.Vote.Options {
		err := validateVoteBit(sv.Vote, v.Bits)
		if err != nil {
			log.Debugf("verifyStartVoteV2: validateVoteBit '%v': %v",
				v.Id, err)
			return www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropVoteBits,
			}
		}
	}

	// Validate vote params
	switch {
	case sv.Vote.Duration < voteDurationMin:
		e := fmt.Sprintf("vote duration must be >= %v",
			voteDurationMin)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{e},
		}
	case sv.Vote.Duration > voteDurationMax:
		e := fmt.Sprintf("vote duration must be <= %v",
			voteDurationMax)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{e},
		}
	case sv.Vote.QuorumPercentage > 100:
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{"quorum percentage cannot be >100"},
		}
	case sv.Vote.PassPercentage > 100:
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{"pass percentage cannot be >100"},
		}
	}

	// Validate signature
	dsv := convertStartVoteV2ToDecred(sv)
	err := dsv.VerifySignature()
	if err != nil {
		log.Debugf("verifyStartVoteV2: VerifySignature: %v", err)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	return nil
}

// verifyVoteOptionsApproveReject verifies that the provided vote options
// specify a simple approve/reject vote and nothing else. A UserError is
// returned if this validation fails.
func verifyVoteOptionsApproveReject(options []www2.VoteOption) error {
	if len(options) == 0 {
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidVoteOptions,
			ErrorContext: []string{"no vote options found"},
		}
	}
	optionIDs := map[string]bool{
		decredplugin.VoteOptionIDApprove: false,
		decredplugin.VoteOptionIDReject:  false,
	}
	for _, vo := range options {
		if _, ok := optionIDs[vo.Id]; !ok {
			e := fmt.Sprintf("invalid vote option id '%v'", vo.Id)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidVoteOptions,
				ErrorContext: []string{e},
			}
		}
		optionIDs[vo.Id] = true
	}
	for k, wasFound := range optionIDs {
		if !wasFound {
			e := fmt.Sprintf("missing vote option id '%v'", k)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidVoteOptions,
				ErrorContext: []string{e},
			}
		}
	}
	return nil
}

// processStartVoteV2 starts the voting period on a proposal using the provided
// v2 StartVote. Proposals that are RFP submissions cannot use this route. They
// must sue the StartVoteRunoff route.
func (p *politeiawww) processStartVoteV2(sv www2.StartVote, u *user.User) (*www2.StartVoteReply, error) {
	log.Tracef("processStartVoteV2 %v", sv.Vote.Token)

	// Sanity check
	if !u.Admin {
		return nil, fmt.Errorf("user is not an admin")
	}

	// Validate the StartVote. We only allow a simple approve/reject
	// vote for now.
	err := verifyStartVoteV2(sv, p.cfg.VoteDurationMin, p.cfg.VoteDurationMax)
	if err != nil {
		return nil, err
	}
	err = verifyVoteOptionsApproveReject(sv.Vote.Options)
	if err != nil {
		return nil, err
	}
	if sv.Vote.Type != www2.VoteTypeStandard {
		e := fmt.Sprintf("vote type must be %v", www2.VoteTypeStandard)
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidVoteType,
			ErrorContext: []string{e},
		}
	}

	// Ensure the public key is the user's active key
	if sv.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate proposal version and status
	pr, err := p.getProp(sv.Vote.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	if pr.Version != strconv.FormatUint(uint64(sv.Vote.ProposalVersion), 10) {
		e := fmt.Sprintf("current proposal version is %v", pr.Version)
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidProposalVersion,
			ErrorContext: []string{e},
		}
	}
	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongStatus,
			ErrorContext: []string{"proposal is not public"},
		}
	}

	// Validate vote status
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	vsr, err := p.decredVoteSummary(sv.Vote.Token, bb)
	if err != nil {
		return nil, err
	}
	if !vsr.Authorized {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote not authorized"},
		}
	}
	if vsr.EndHeight != "" {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote already started"},
		}
	}

	// Verify that this is not an RFP submission. The voting
	// period for RFP submissions can only be started using
	// the StartVoteRunoff route.
	if isRFPSubmission(pr) {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongProposalType,
			ErrorContext: []string{"cannot be an rfp submission"},
		}
	}

	// Verify the LinkBy deadline for RFP proposals
	if pr.IsRFP() {
		ts := time.Now().Unix() + www.PolicyMinLinkByPeriod
		if pr.LinkBy < ts {
			e := fmt.Sprintf("linkby period must be at least %v seconds from "+
				"the start of the proposal vote", www.PolicyMinLinkByPeriod)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkBy,
				ErrorContext: []string{e},
			}
		}
	}

	// Tell decred plugin to start voting
	dsv := convertStartVoteV2ToDecred(sv)
	payload, err := decredplugin.EncodeStartVoteV2(dsv)
	if err != nil {
		return nil, err
	}
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdStartVote,
		CommandID: decredplugin.CmdStartVote + " " + sv.Vote.Token,
		Payload:   string(payload),
	}
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle reply
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal "+
			"PluginCommandReply: %v", err)
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}
	dsvr, err := decredplugin.DecodeStartVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	svr, err := convertStartVoteReplyV2FromDecred(*dsvr)
	if err != nil {
		return nil, err
	}

	// Fire off start vote event
	p.fireEvent(EventTypeProposalVoteStarted,
		EventDataProposalVoteStarted{
			AdminUser: u,
			StartVote: sv,
		},
	)

	return svr, nil
}

// voteIsApproved returns whether the provided VoteSummary met the quorum
// and pass requirements. This function should only be called on simple
// approve/reject votes that use the decredplugin VoteOptionIDApprove.
func voteIsApproved(vs www.VoteSummary) bool {
	if vs.Status != www.PropVoteStatusFinished {
		// Vote has not ended yet
		return false
	}

	var (
		total   uint64
		approve uint64
	)
	for _, v := range vs.Results {
		total += v.VotesReceived
		if v.Option.Id == decredplugin.VoteOptionIDApprove {
			approve = v.VotesReceived
		}
	}
	quorum := uint64(float64(vs.QuorumPercentage) / 100 * float64(vs.EligibleTickets))
	pass := uint64(float64(vs.PassPercentage) / 100 * float64(total))
	switch {
	case total < quorum:
		// Quorum not met
		return false
	case approve < pass:
		// Pass percentage not met
		return false
	}

	return true
}

// processStartVoteRunoffV2 starts the runoff voting process on all public,
// non-abandoned RFP submissions for the provided RFP token. If politeiad fails
// to start the voting period on any of the RFP submissions, all work is
// unwound and an error is returned.
func (p *politeiawww) processStartVoteRunoffV2(sv www2.StartVoteRunoff, u *user.User) (*www2.StartVoteRunoffReply, error) {
	log.Tracef("processStartVoteRFP %v", sv.Token)

	// Sanity check
	if !u.Admin {
		return nil, fmt.Errorf("user is not an admin")
	}

	// Validate the StartVotes
	for _, v := range sv.StartVotes {
		err := verifyStartVoteV2(v, p.cfg.VoteDurationMin, p.cfg.VoteDurationMax)
		if err != nil {
			return nil, err
		}

		// Ensure admin signed using their active identity
		if v.PublicKey != u.PublicKey() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidSigningKey,
			}
		}

		// Vote options must be approve/reject and nothing else
		err = verifyVoteOptionsApproveReject(v.Vote.Options)
		if err != nil {
			return nil, err
		}

		// Vote type must be a runoff vote
		if v.Vote.Type != www2.VoteTypeRunoff {
			e := fmt.Sprintf("vote type must be %v", www2.VoteTypeRunoff)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidVoteType,
				ErrorContext: []string{e},
			}
		}
	}

	// Validate the RFP proposal
	rfp, err := p.getProp(sv.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode:    www.ErrorStatusProposalNotFound,
				ErrorContext: []string{sv.Token},
			}
		}
		return nil, err
	}
	bestBlock, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	rfpVoteSummary, err := p.getVoteSummary(sv.Token, bestBlock)
	if err != nil {
		return nil, err
	}

	switch {
	case !voteIsApproved(*rfpVoteSummary):
		// The RFP submissions can only be voted on if the RFP
		// proposal itself has been voted on and approved.
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteResult,
			ErrorContext: []string{"rfp proposal vote did not pass"},
		}
	case rfp.LinkBy < time.Now().Unix():
		// Vote cannot start on RFP submissions until the RFP
		// linkby deadline has been met.
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusLinkByDeadlineNotMet,
			ErrorContext: []string{"linkby deadline not met"},
		}
	case len(rfp.LinkedFrom) == 0:
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusNoLinkedProposals,
			ErrorContext: []string{"no rfp submissions found"},
		}
	}

	// Compile a list of the public, non-abandoned RFP submissions.
	// This list will be used to ensure a StartVote exists for each
	// of the public, non-abandoned submissions.
	linkedFromProps, err := p.getProps(rfp.LinkedFrom)
	if err != nil {
		return nil, err
	}
	submissions := make(map[string]bool, len(rfp.LinkedFrom)) // [token]startVoteFound
	for _, v := range linkedFromProps {
		// Filter out abandoned submissions. The vote cannot
		// be started on these.
		if v.Status != www.PropStatusPublic {
			continue
		}

		// Set to false for now until we check that a StartVote
		// was included for this proposal.
		submissions[v.CensorshipRecord.Token] = false
	}

	// Verify that a StartVote exists for all public, non-abandoned
	// submissions and that there are no extra StartVotes.
	for _, v := range sv.StartVotes {
		_, ok := submissions[v.Vote.Token]
		if !ok {
			e := fmt.Sprintf("proposal cannot be part of the runoff vote: %v",
				v.Vote.Token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}

		// A StartVote was included for this proposal
		submissions[v.Vote.Token] = true
	}
	for token, startVoteFound := range submissions {
		if !startVoteFound {
			e := fmt.Sprintf("missing start vote for rfp submission: %v",
				token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}
	}

	// Compile RFP submission proposals and their vote summaries
	subTokens := make([]string, 0, len(submissions))
	subProps := make(map[string]www.ProposalRecord, len(subTokens)) // [token]ProposalRecord
	for token := range submissions {
		subTokens = append(subTokens, token)
		subProps[token] = linkedFromProps[token]
	}
	subVotes, err := p.getVoteSummaries(subTokens, bestBlock)
	if err != nil {
		return nil, err
	}

	// Validate RFP submissions. It should not be possible for an RFP
	// submission to get into any of the below states so these checks
	// are all just sanity checks.
	for _, v := range sv.StartVotes {
		// Validate submission proposal
		pr, ok := subProps[v.Vote.Token]
		if !ok {
			return nil, fmt.Errorf("proposal not found: %v",
				v.Vote.Token)
		}
		switch {
		case pr.Status != www.PropStatusPublic:
			// While its possible for an RFP submission to not be
			// public, the StartVote validation above should have
			// already filtered these proposals so this code path
			// should never be hit.
			return nil, fmt.Errorf("rfp submission not public: %v",
				v.Vote.Token)
		case pr.LinkTo != sv.Token:
			return nil, fmt.Errorf("proposal not linked to rfp: %v %v",
				pr.LinkTo, sv.Token)
		}

		// Validate submission vote status
		vs, ok := subVotes[v.Vote.Token]
		if !ok {
			return nil, fmt.Errorf("vote summary not found: %v",
				v.Vote.Token)
		}
		if vs.Status != www.PropVoteStatusNotAuthorized {
			return nil, fmt.Errorf("got vote status %v, want %v for %v",
				vs.Status, www.PropVoteStatusNotAuthorized, v.Vote.Token)
		}
	}

	// Setup plugin command
	dsv := convertStartVotesV2ToDecred(sv.StartVotes)
	payload, err := decredplugin.EncodeStartVoteRunoff(
		decredplugin.StartVoteRunoff{
			Token:      sv.Token,
			StartVotes: dsv,
		})
	if err != nil {
		return nil, err
	}
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdStartVoteRunoff,
		Payload:   string(payload),
	}

	// Send plugin command
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}
	dsvr, err := decredplugin.DecodeStartVoteRunoffReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	svr, err := convertStartVoteReplyV2FromDecred(dsvr.StartVoteReply)
	if err != nil {
		return nil, err
	}

	// Fire off a start vote events for each rfp submission
	for _, v := range sv.StartVotes {
		p.fireEvent(EventTypeProposalVoteStarted,
			EventDataProposalVoteStarted{
				AdminUser: u,
				StartVote: v,
			},
		)
	}

	return &www2.StartVoteRunoffReply{
		StartBlockHeight: svr.StartBlockHeight,
		StartBlockHash:   svr.StartBlockHash,
		EndBlockHeight:   svr.EndBlockHeight,
		EligibleTickets:  svr.EligibleTickets,
	}, nil
}

// processTokenInventory returns the tokens of all proposals in the inventory,
// categorized by stage of the voting process.
func (p *politeiawww) processTokenInventory(isAdmin bool) (*www.TokenInventoryReply, error) {
	log.Tracef("processTokenInventory")

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}

	// The vote results cache table is lazy loaded and may
	// need to be updated. If it does need to be updated, the
	// token inventory call will need to be retried after the
	// update is complete.
	var done bool
	var r www.TokenInventoryReply
	for retries := 0; !done && retries <= 1; retries++ {
		// Both vetted and unvetted tokens should be returned
		// for admins. Only vetted tokens should be returned
		// for non-admins.
		ti, err := p.decredTokenInventory(bb, isAdmin)
		if err != nil {
			if err == cache.ErrRecordNotFound {
				// There are missing entries in the vote
				// results cache table. Load them.
				_, err := p.decredLoadVoteResults(bb)
				if err != nil {
					return nil, err
				}

				// Retry token inventory call
				continue
			}
			return nil, err
		}

		r = convertTokenInventoryReplyFromDecred(*ti)
		done = true
	}

	return &r, err
}

// processVoteDetailsV2 returns the vote details for the given proposal token.
func (p *politeiawww) processVoteDetailsV2(token string) (*www2.VoteDetailsReply, error) {
	log.Tracef("processVoteDetailsV2: %v", token)

	// Validate vote status
	dvdr, err := p.decredVoteDetails(token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	if dvdr.StartVoteReply.StartBlockHash == "" {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"voting has not started yet"},
		}
	}

	// Handle StartVote versioning
	var vdr *www2.VoteDetailsReply
	switch dvdr.StartVote.Version {
	case decredplugin.VersionStartVoteV1:
		b := []byte(dvdr.StartVote.Payload)
		dsv1, err := decredplugin.DecodeStartVoteV1(b)
		if err != nil {
			return nil, err
		}
		vdr, err = convertDecredStartVoteV1ToVoteDetailsReplyV2(*dsv1,
			dvdr.StartVoteReply)
		if err != nil {
			return nil, err
		}
	case decredplugin.VersionStartVoteV2:
		b := []byte(dvdr.StartVote.Payload)
		dsv2, err := decredplugin.DecodeStartVoteV2(b)
		if err != nil {
			return nil, err
		}
		vdr, err = convertDecredStartVoteV2ToVoteDetailsReplyV2(*dsv2,
			dvdr.StartVoteReply)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("invalid StartVote version %v %v",
			token, dvdr.StartVote.Version)
	}

	return vdr, nil
}
