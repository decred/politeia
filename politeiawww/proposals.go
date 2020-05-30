// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/cache"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	www2 "github.com/decred/politeia/politeiawww/api/www/v2"
	"github.com/decred/politeia/politeiawww/user"
	wwwutil "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
)

const (
	// MIME types
	mimeTypeText     = "text/plain"
	mimeTypeTextUTF8 = "text/plain; charset=utf-8"
	mimeTypePNG      = "image/png"
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

// convertMetadataFromFile returns a politeiad File that was converted from a
// politiawww v1 Metadata. User specified metadata is store as a file in
// politeiad so that it is included in the merkle root that politeiad
// calculates.
func convertFileFromMetadata(m www.Metadata) pd.File {
	var name string
	switch m.Hint {
	case www.HintProposalMetadata:
		name = mdstream.FilenameProposalMetadata
	}
	return pd.File{
		Name:    name,
		MIME:    mimeTypeTextUTF8,
		Digest:  m.Digest,
		Payload: m.Payload,
	}
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

// isProposalAuthor returns whether the provided user is the author of the
// provided proposal.
func isProposalAuthor(pr www.ProposalRecord, u user.User) bool {
	var isAuthor bool
	for _, v := range u.Identities {
		if v.String() == pr.PublicKey {
			isAuthor = true
		}
	}
	return isAuthor
}

// isRFP returns whether the proposal is a Request For Proposals (RFP).
func isRFP(pr www.ProposalRecord) bool {
	return pr.LinkBy != 0
}

func isRFPSubmission(pr www.ProposalRecord) bool {
	// Right now the only proposals that we allow linking to
	// are RFPs so if the linkto is set than this is an RFP
	// submission. This may change in the future, at which
	// point we'll actually have to check the linkto proposal
	// to see if its an RFP.
	return pr.LinkTo != ""
}

// isTokenValid returns whether the provided string is a valid politeiad
// censorship record token.
func isTokenValid(token string) bool {
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
		if !isTokenValid(token) {
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

// linkByPeriodMin returns the minimum amount of time, in seconds, that the
// LinkBy period must be set to. This is determined by adding 1 week onto the
// minimum voting period so that RFP proposal submissions have at least one
// week to be submitted after the proposal vote ends.
func (p *politeiawww) linkByPeriodMin() int64 {
	var (
		submissionPeriod int64 = 604800 // One week in seconds
		avgBlockTime     int64 = 300    // 5 minutes in seconds
	)
	return (int64(p.cfg.VoteDurationMin) * avgBlockTime) + submissionPeriod
}

// linkByPeriodMax returns the maximum amount of time, in seconds, that the
// LinkBy period can be set to. 3 months is currently hard coded with no real
// reason for deciding on 3 months besides that it sounds like a sufficient
// amount of time.  This can be changed if there is a valid reason to.
func (p *politeiawww) linkByPeriodMax() int64 {
	return 7776000 // 3 months in seconds
}

func (p *politeiawww) validateProposalMetadata(pm www.ProposalMetadata) error {
	// Validate Name
	if !isValidProposalName(pm.Name) {
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalInvalidTitle,
			ErrorContext: []string{createProposalNameRegex()},
		}
	}

	// Validate LinkTo
	if pm.LinkTo != "" {
		if !isTokenValid(pm.LinkTo) {
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"invalid token"},
			}
		}

		// Validate the LinkTo proposal. The only type of proposal
		// that we currently allow linking to is an RFP.
		r, err := p.cache.Record(pm.LinkTo)
		if err != nil {
			if err == cache.ErrRecordNotFound {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvalidLinkTo,
				}
			}
		}
		pr, err := convertPropFromCache(*r)
		if err != nil {
			return err
		}
		bb, err := p.getBestBlock()
		if err != nil {
			return err
		}
		vs, err := p.voteSummaryGet(pm.LinkTo, bb)
		if err != nil {
			return err
		}
		switch {
		case !isRFP(*pr):
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"linkto proposal is not an rfp"},
			}
		case !voteIsApproved(*vs):
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"rfp proposal vote did not pass"},
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
		case isRFP(*pr) && pm.LinkBy != 0:
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"an rfp cannot link to an rfp"},
			}
		}
	}

	// Validate LinkBy
	if pm.LinkBy != 0 {
		min := time.Now().Unix() + p.linkByPeriodMin()
		max := time.Now().Unix() + p.linkByPeriodMax()
		switch {
		case pm.LinkBy < min:
			e := fmt.Sprintf("linkby period cannot be shorter than %v seconds",
				p.linkByPeriodMin())
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkBy,
				ErrorContext: []string{e},
			}
		case pm.LinkBy > max:
			e := fmt.Sprintf("linkby period cannot be greater than %v seconds",
				p.linkByPeriodMax())
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
func (p *politeiawww) validateProposal(np www.NewProposal, u *user.User) (*www.ProposalMetadata, error) {
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
	)
	filenames := make(map[string]struct{}, len(np.Files))
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

			// The only text file that is allowed is the index markdown
			// file.
			if v.Name != www.PolicyIndexFilename {
				return nil, www.UserError{
					ErrorCode:    www.ErrorStatusMaxMDsExceededPolicy,
					ErrorContext: []string{v.Name},
				}
			}
			if foundIndexFile {
				e := fmt.Sprintf("more than one %v file found",
					www.PolicyIndexFilename)
				return nil, www.UserError{
					ErrorCode:    www.ErrorStatusMaxMDsExceededPolicy,
					ErrorContext: []string{e},
				}
			}

			// Set index file as being found
			foundIndexFile = true

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

	// Verify that an index file is present.
	if !foundIndexFile {
		e := fmt.Sprintf("%v file not found", www.PolicyIndexFilename)
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

	// Decode and validate metadata
	var pm *www.ProposalMetadata
	for _, v := range np.Metadata {
		// Decode payload
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			e := fmt.Sprintf("invalid base64 for '%v'", v.Hint)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusMetadataInvalid,
				ErrorContext: []string{e},
			}
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()

		// Unmarshal payload
		switch v.Hint {
		case www.HintProposalMetadata:
			var p www.ProposalMetadata
			err := d.Decode(&p)
			if err != nil {
				log.Debugf("validateProposal: decode ProposalMetadata: %v", err)
				return nil, www.UserError{
					ErrorCode:    www.ErrorStatusMetadataInvalid,
					ErrorContext: []string{v.Hint},
				}
			}
			pm = &p
		default:
			e := fmt.Sprintf("unknown hint '%v'", v.Hint)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusMetadataInvalid,
				ErrorContext: []string{e},
			}
		}

		// Validate digest
		digest := util.Digest(b)
		if v.Digest != hex.EncodeToString(digest) {
			e := fmt.Sprintf("%v got digest %v, want %v",
				v.Hint, v.Digest, hex.EncodeToString(digest))
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusMetadataDigestInvalid,
				ErrorContext: []string{e},
			}
		}
	}
	if pm == nil {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusMetadataMissing,
			ErrorContext: []string{www.HintProposalMetadata},
		}
	}

	// Validate ProposalMetadata
	err := p.validateProposalMetadata(*pm)
	if err != nil {
		return nil, err
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
	mr, err := wwwutil.MerkleRoot(np.Files, np.Metadata)
	if err != nil {
		return nil, err
	}
	if !pk.VerifyMessage([]byte(mr), sig) {
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

	return pm, nil
}

func voteStatusFromVoteSummary(r decredplugin.VoteSummaryReply, endHeight, bestBlock uint64) www.PropVoteStatusT {
	switch {
	case !r.Authorized:
		return www.PropVoteStatusNotAuthorized
	case r.Authorized && endHeight == 0:
		return www.PropVoteStatusAuthorized
	case bestBlock < endHeight:
		return www.PropVoteStatusStarted
	case bestBlock >= endHeight:
		return www.PropVoteStatusFinished
	}

	return www.PropVoteStatusInvalid
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

// fillProposalMissingFields populates a ProposalRecord struct with the fields
// that are not stored in the cache.
func (p *politeiawww) fillProposalMissingFields(pr *www.ProposalRecord) error {
	// Find the number of comments for the proposal
	nc, err := p.decredGetNumComments([]string{pr.CensorshipRecord.Token})
	if err != nil {
		return err
	}
	pr.NumComments = uint(nc[pr.CensorshipRecord.Token])

	// Fill in proposal author info
	u, err := p.db.UserGetByPubKey(pr.PublicKey)
	if err != nil {
		return err
	}
	pr.UserId = u.ID.String()
	pr.Username = u.Username

	// Find linked from proposals
	lfr, err := p.decredLinkedFrom([]string{pr.CensorshipRecord.Token})
	if err != nil {
		return err
	}
	linkedFrom, ok := lfr.LinkedFrom[pr.CensorshipRecord.Token]
	if ok {
		pr.LinkedFrom = linkedFrom
	}

	return nil
}

// getProp gets the most recent verions of the given proposal from the cache
// then fills in any missing fields before returning the proposal.
func (p *politeiawww) getProp(token string) (*www.ProposalRecord, error) {
	log.Tracef("getProp: %v", token)

	var r *cache.Record
	var err error
	if len(token) == www.TokenPrefixLength {
		r, err = p.cache.RecordByPrefix(token)
	} else {
		r, err = p.cache.Record(token)
	}
	if err != nil {
		return nil, err
	}

	pr, err := convertPropFromCache(*r)
	if err != nil {
		return nil, err
	}

	err = p.fillProposalMissingFields(pr)
	if err != nil {
		return nil, err
	}

	return pr, nil
}

// getPropAllVersions retrieves all versions of a proposal from the cache. This
// function does NOT call fillProposalMissingFields.
func (p *politeiawww) getPropAllVersions(token string) (map[uint64]www.ProposalRecord, error) {
	log.Tracef("getPropAllVersions: %v", token)

	cacheRecords, err := p.cache.RecordAllVersions(token, false)
	if err != nil {
		return nil, err
	}

	wwwRecords := make(map[uint64]www.ProposalRecord)
	for version, record := range cacheRecords {
		wwwRecord, err := convertPropFromCache(record)
		if err != nil {
			return nil, err
		}
		wwwRecords[version] = *wwwRecord
	}

	return wwwRecords, nil
}

// getProps returns a [token]www.ProposalRecord map for the provided list of
// censorship tokens. If a proposal is not found, the map will not include an
// entry for the corresponding censorship token. It is the responsibility of
// the caller to ensure that results are returned for all of the provided
// censorship tokens.
func (p *politeiawww) getProps(tokens []string) (map[string]www.ProposalRecord, error) {
	log.Tracef("getProps: %v", tokens)

	// Get the proposals from the cache
	records, err := p.cache.Records(tokens, true)
	if err != nil {
		return nil, err
	}

	// Use pointers for now so the props can be easily updated
	props := make(map[string]*www.ProposalRecord, len(records))
	for _, v := range records {
		pr, err := convertPropFromCache(v)
		if err != nil {
			return nil, fmt.Errorf("convertPropFromCache %v: %v",
				v.CensorshipRecord.Token, err)
		}
		props[v.CensorshipRecord.Token] = pr
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
func (p *politeiawww) getPropVersion(token, version string, fillMissingFields bool) (*www.ProposalRecord, error) {
	log.Tracef("getPropVersion: %v %v", token, version)

	r, err := p.cache.RecordVersion(token, version)
	if err != nil {
		return nil, err
	}

	pr, err := convertPropFromCache(*r)
	if err != nil {
		return nil, err
	}

	if fillMissingFields {
		err = p.fillProposalMissingFields(pr)
		if err != nil {
			return nil, err
		}
	}

	return pr, nil
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
		pr, err := convertPropFromCache(v)
		if err != nil {
			return nil, fmt.Errorf("convertPropFromCache %v: %v",
				pr.CensorshipRecord.Token, err)
		}
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

		props = append(props, *pr)
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

// voteSummariesGet returns a map[string]www.VoteSummary for the given proposal
// tokens. An entry in the returned map will only exist for tokens where a
// proposal record was found.
//
// This function must be called WITHOUT read/write lock held.
func (p *politeiawww) voteSummariesGet(tokens []string, bestBlock uint64) (map[string]www.VoteSummary, error) {
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

	// Fetch the vote summaries from the cache. This call relies on the
	// lazy loaded VoteResults cache table. If the VoteResults table is
	// not up-to-date then this function will load it before retrying
	// the vote summary call. Since politeiawww only has read access to
	// the cache, loading the VoteResults table requires using a
	// politeiad decredplugin command.
	var (
		done  bool
		err   error
		reply *decredplugin.BatchVoteSummaryReply
	)
	for retries := 0; !done && retries <= 1; retries++ {
		reply, err = p.decredBatchVoteSummary(tokensToLookup, bestBlock)
		if err != nil {
			if err == cache.ErrRecordNotFound {
				// There are missing entries in the VoteResults
				// cache table. Load them.
				_, err := p.decredLoadVoteResults(bestBlock)
				if err != nil {
					return nil, err
				}

				// Retry the vote summaries call
				continue
			}
			return nil, err
		}

		done = true
	}

	for token, v := range reply.Summaries {
		results := convertVoteOptionResultsFromDecred(v.Results)
		votet := convertVoteTypeFromDecred(v.Type)

		// An endHeight will not exist if the proposal has not gone
		// up for vote yet.
		var endHeight uint64
		if v.EndHeight != "" {
			i, err := strconv.ParseUint(v.EndHeight, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse end height "+
					"'%v' for %v: %v", v.EndHeight, token, err)
			}
			endHeight = i
		}

		vs := www.VoteSummary{
			Status:           voteStatusFromVoteSummary(v, endHeight, bestBlock),
			Type:             www.VoteT(int(votet)),
			Approved:         v.Approved,
			EligibleTickets:  uint32(v.EligibleTicketCount),
			Duration:         v.Duration,
			EndHeight:        endHeight,
			QuorumPercentage: v.QuorumPercentage,
			PassPercentage:   v.PassPercentage,
			Results:          results,
		}

		voteSummaries[token] = vs

		// If the voting period has ended the vote status
		// is not going to change so add it to the memory
		// cache.
		if vs.Status == www.PropVoteStatusFinished {
			p.voteSummarySet(token, vs)
		}
	}

	return voteSummaries, nil
}

// voteSummaryGet stores the provided VoteSummary in the vote summaries memory
// cache. This is to only be used for proposals whose voting period has ended
// so that we don't have to worry about cache invalidation issues.
//
// This function must be called WITHOUT the read/write lock held.
func (p *politeiawww) voteSummarySet(token string, voteSummary www.VoteSummary) {
	p.Lock()
	defer p.Unlock()

	p.voteSummaries[token] = voteSummary
}

// voteSummaryGet returns the VoteSummary for the given token. A cache
// ErrRecordNotFound error is returned if the token does actually not
// correspond to a proposal.
//
// This function must be called WITHOUT the read/write lock held.
func (p *politeiawww) voteSummaryGet(token string, bestBlock uint64) (*www.VoteSummary, error) {
	s, err := p.voteSummariesGet([]string{token}, bestBlock)
	if err != nil {
		return nil, err
	}
	vs, ok := s[token]
	if !ok {
		return nil, cache.ErrRecordNotFound
	}
	return &vs, nil
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

	pm, err := p.validateProposal(np, user)
	if err != nil {
		return nil, err
	}

	// politeiad only includes files in its merkle root calc, not the
	// metadata streams. This is why we include the ProposalMetadata
	// as a politeiad file.

	// Setup politeaid files
	files := convertPropFilesFromWWW(np.Files)
	for _, v := range np.Metadata {
		switch v.Hint {
		case www.HintProposalMetadata:
			files = append(files, convertFileFromMetadata(v))
		}
	}

	// Setup politeiad metadata
	pg := mdstream.ProposalGeneralV2{
		Version:   mdstream.VersionProposalGeneral,
		Timestamp: time.Now().Unix(),
		PublicKey: np.PublicKey,
		Signature: np.Signature,
	}
	pgb, err := mdstream.EncodeProposalGeneralV2(pg)
	if err != nil {
		return nil, err
	}
	metadata := []pd.MetadataStream{
		{
			ID:      mdstream.IDProposalGeneral,
			Payload: string(pgb),
		},
	}

	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	n := pd.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata:  metadata,
		Files:     files,
	}

	// Send politeiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.NewRecordRoute, n)
	if err != nil {
		return nil, err
	}

	log.Infof("Submitted proposal name: %v", pm.Name)
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
			ProposalName:     pm.Name,
			User:             user,
		},
	)

	return &www.NewProposalReply{
		CensorshipRecord: cr,
	}, nil
}

// getLinkingTimestamps looks up the proposals that were linked to an RFP
// proposal and the timestamps when they were published.
func (p *politeiawww) getLinkingTimestamps(token string) ([]www.LinkingTimestamp, error) {
	lfr, err := p.decredLinkedFrom([]string{token})
	if err != nil {
		return nil, err
	}

	linkedFrom := lfr.LinkedFrom[token]
	linkingTimestamps := make([]www.LinkingTimestamp, 0, len(linkedFrom))

	for _, linkedToken := range linkedFrom {
		prop, err := p.getPropVersion(linkedToken, "1", false)
		if err != nil {
			return nil, err
		}

		linkingTimestamps = append(linkingTimestamps, www.LinkingTimestamp{
			Timestamp: uint64(prop.PublishedAt),
			Token:     linkedToken,
		})
	}

	return linkingTimestamps, nil
}

// processProposalTimeline retrieves the timeline of events related to a
// proposal.
func (p *politeiawww) processProposalTimeline(pt www.ProposalTimeline) (*www.ProposalTimelineReply, error) {
	log.Tracef("processProposalTimeline")

	records, err := p.getPropAllVersions(pt.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	reply := www.ProposalTimelineReply{}

	// Get the timestamps when each version was created and vetted
	reply.VersionTimestamps = make([]www.VersionTimestamp, len(records))
	for version, record := range records {
		if version < 1 || version > uint64(len(records)) {
			return nil, fmt.Errorf("invalid version of record: %v", version)
		}
		reply.VersionTimestamps[version-1].Created = uint64(record.CreatedAt)
		reply.VersionTimestamps[version-1].Vetted = uint64(record.PublishedAt)
	}

	// Get the start and end blocks of the voting period
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	vs, err := p.voteSummaryGet(pt.Token, bb)
	if err != nil {
		return nil, err
	}
	if vs.EndHeight > 0 {
		reply.EndVoteBlock = uint32(vs.EndHeight)
		reply.StartVoteBlock = reply.EndVoteBlock - vs.Duration
	}

	// If this is an RFP proposal, get the timestamps when proposals were
	// linked with this one
	linkingTimestamps, err := p.getLinkingTimestamps(pt.Token)
	if err != nil {
		return nil, err
	}
	reply.LinkingTimestamps = linkingTimestamps

	return &reply, nil
}

// createProposalDetailsReply makes updates to a proposal record based on the
// user who made the request, and puts it into a ProposalDetailsReply.
func createProposalDetailsReply(prop *www.ProposalRecord, user *user.User) *www.ProposalDetailsReply {
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
			prop.Name = ""
			prop.Files = make([]www.File, 0)
		}
	}

	return &www.ProposalDetailsReply{
		Proposal: *prop,
	}
}

// processProposalDetails fetches a specific proposal version from the records
// cache and returns it.
func (p *politeiawww) processProposalDetails(propDetails www.ProposalsDetails, user *user.User) (*www.ProposalDetailsReply, error) {
	log.Tracef("processProposalDetails: %v", propDetails.Token)

	// Version is an optional query param. Fetch latest version
	// when query param is not specified.
	var prop *www.ProposalRecord
	var err error
	if propDetails.Version == "" {
		prop, err = p.getProp(propDetails.Token)
	} else {
		prop, err = p.getPropVersion(propDetails.Token, propDetails.Version, true)
	}
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	return createProposalDetailsReply(prop, user), nil
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

	summaries, err := p.voteSummariesGet(batchVoteSummary.Tokens, bb)
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
		if !isTokenValid(v) {
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
		vs, err := p.voteSummaryGet(pr.CensorshipRecord.Token, bb)
		if err != nil {
			return nil, err
		}
		switch {
		case vs.EndHeight != 0:
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusWrongVoteStatus,
				ErrorContext: []string{"vote has started"},
			}
		case vs.Status == www.PropVoteStatusAuthorized:
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
	updatedProp, err := p.getPropVersion(pr.CensorshipRecord.Token, pr.Version,
		true)
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

// filesToDel returns the names of the files that are included in filesOld but
// are not included in filesNew. These are the files that need to be deleted
// from a proposal on update.
func filesToDel(filesOld []www.File, filesNew []www.File) []string {
	newf := make(map[string]struct{}, len(filesOld)) // [name]struct
	for _, v := range filesNew {
		newf[v.Name] = struct{}{}
	}

	del := make([]string, 0, len(filesOld))
	for _, v := range filesOld {
		_, ok := newf[v.Name]
		if !ok {
			del = append(del, v.Name)
		}
	}

	return del
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
	vs, err := p.voteSummaryGet(ep.Token, bb)
	if err != nil {
		return nil, err
	}
	if vs.Status != www.PropVoteStatusNotAuthorized {
		e := fmt.Sprintf("got vote status %v, want %v",
			vs.Status, www.PropVoteStatusNotAuthorized)
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{e},
		}
	}

	// Validate proposal. Convert it to www.NewProposal so that
	// we can reuse the function validateProposal.
	np := www.NewProposal{
		Files:     ep.Files,
		Metadata:  ep.Metadata,
		PublicKey: ep.PublicKey,
		Signature: ep.Signature,
	}

	pm, err := p.validateProposal(np, u)
	if err != nil {
		return nil, err
	}
	// Check if there were changes in the proposal by comparing
	// their merkle roots. This captures changes that were made
	// to either the files or the metadata.
	mr, err := wwwutil.MerkleRoot(ep.Files, ep.Metadata)
	if err != nil {
		return nil, err
	}
	if cachedProp.CensorshipRecord.Merkle == mr {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoProposalChanges,
		}
	}
	if cachedProp.State == www.PropStateVetted &&
		cachedProp.LinkTo != pm.LinkTo {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidLinkTo,
			ErrorContext: []string{"linkto cannot change once public"},
		}
	}

	// politeiad only includes files in its merkle root calc, not the
	// metadata streams. This is why we include the ProposalMetadata
	// as a politeiad file.

	// Setup files
	files := convertPropFilesFromWWW(ep.Files)
	for _, v := range ep.Metadata {
		switch v.Hint {
		case www.HintProposalMetadata:
			files = append(files, convertFileFromMetadata(v))
		}
	}

	// Setup metadata streams
	pg := mdstream.ProposalGeneralV2{
		Version:   mdstream.VersionProposalGeneral,
		Timestamp: time.Now().Unix(),
		PublicKey: ep.PublicKey,
		Signature: ep.Signature,
	}
	pgb, err := mdstream.EncodeProposalGeneralV2(pg)
	if err != nil {
		return nil, err
	}
	mds := []pd.MetadataStream{
		{
			ID:      mdstream.IDProposalGeneral,
			Payload: string(pgb),
		},
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
		FilesAdd:    files,
		FilesDel:    filesToDel(cachedProp.Files, ep.Files),
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
	if (v.Before != "" && !isTokenValid(v.Before)) ||
		(v.After != "" && !isTokenValid(v.After)) {
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
	vs, err := p.voteSummaryGet(token, bestBlock)
	if err != nil {
		return nil, err
	}

	var total uint64
	for _, v := range vs.Results {
		total += v.VotesReceived
	}

	voteStatusReply := www.VoteStatusReply{
		Token:              token,
		Status:             vs.Status,
		TotalVotes:         total,
		OptionsResult:      vs.Results,
		EndHeight:          strconv.Itoa(int(vs.EndHeight)),
		BestBlock:          strconv.Itoa(int(bestBlock)),
		NumOfEligibleVotes: int(vs.EligibleTickets),
		QuorumPercentage:   vs.QuorumPercentage,
		PassPercentage:     vs.PassPercentage,
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
	tir, err := p.tokenInventory(bb, false)
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

// validateAuthorizeVote validates the authorize vote fields. A UserError is
// returned if any of the validation fails.
func validateAuthorizeVote(av www.AuthorizeVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary) error {
	// Ensure the public key is the user's active key
	if av.PublicKey != u.PublicKey() {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := av.Token + pr.Version + av.Action
	err := validateSignature(av.PublicKey, av.Signature, msg)
	if err != nil {
		return err
	}

	// Verify record is in the right state and that the authorize
	// vote request is valid. A vote authorization may already
	// exist. We also allow vote authorizations to be revoked.
	switch {
	case pr.Status != www.PropStatusPublic:
		// Record not public
		return www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	case vs.EndHeight != 0:
		// Vote has already started
		return www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	case av.Action != decredplugin.AuthVoteActionAuthorize &&
		av.Action != decredplugin.AuthVoteActionRevoke:
		// Invalid authorize vote action
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidAuthVoteAction,
		}
	case av.Action == decredplugin.AuthVoteActionAuthorize &&
		vs.Status == www.PropVoteStatusAuthorized:
		// Cannot authorize vote; vote has already been authorized
		return www.UserError{
			ErrorCode: www.ErrorStatusVoteAlreadyAuthorized,
		}
	case av.Action == decredplugin.AuthVoteActionRevoke &&
		vs.Status != www.PropVoteStatusAuthorized:
		// Cannot revoke authorization; vote has not been authorized
		return www.UserError{
			ErrorCode: www.ErrorStatusVoteNotAuthorized,
		}
	}

	return nil
}

// validateAuthorizeVoteRunoff validates the authorize vote for a proposal that
// is participating in a standard vote. A UserError is returned if any of the
// validation fails.
func validateAuthorizeVoteStandard(av www.AuthorizeVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary) error {
	err := validateAuthorizeVote(av, u, pr, vs)
	if err != nil {
		return err
	}

	// The rest of the validation is specific to authorize votes for
	// standard votes.
	switch {
	case isRFPSubmission(pr):
		// Wrong validation function used. Fail with a 500.
		return fmt.Errorf("proposal is a runoff vote submission")
	case pr.PublicKey != av.PublicKey:
		// User is not the author. First make sure the author didn't
		// submit the proposal using an old identity.
		if !isProposalAuthor(pr, u) {
			return www.UserError{
				ErrorCode: www.ErrorStatusUserNotAuthor,
			}
		}
	}

	return nil
}

// validateAuthorizeVoteRunoff validates the authorize vote for a proposal that
// is participating in a runoff vote. A UserError is returned if any of the
// validation fails.
func validateAuthorizeVoteRunoff(av www.AuthorizeVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary) error {
	err := validateAuthorizeVote(av, u, pr, vs)
	if err != nil {
		return err
	}

	// The rest of the validation is specific to authorize votes for
	// runoff votes.
	switch {
	case !u.Admin:
		// User is not an admin
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidSigningKey,
			ErrorContext: []string{"user not an admin"},
		}
	}

	return nil
}

// processAuthorizeVote sends the authorizevote command to decred plugin to
// indicate that a proposal has been finalized and is ready to be voted on.
func (p *politeiawww) processAuthorizeVote(av www.AuthorizeVote, u *user.User) (*www.AuthorizeVoteReply, error) {
	log.Tracef("processAuthorizeVote %v", av.Token)

	// Validate the vote authorization
	pr, err := p.getProp(av.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	vs, err := p.voteSummaryGet(av.Token, bb)
	if err != nil {
		return nil, err
	}
	err = validateAuthorizeVoteStandard(av, *u, *pr, *vs)
	if err != nil {
		return nil, err
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, fmt.Errorf("Random: %v", err)
	}

	dav := convertAuthorizeVoteToDecred(av)
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

// validateVoteOptions verifies that the provided vote options
// specify a simple approve/reject vote and nothing else. A UserError is
// returned if this validation fails.
func validateVoteOptions(options []www2.VoteOption) error {
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

func validateStartVote(sv www2.StartVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary, durationMin, durationMax uint32) error {
	if !isTokenValid(sv.Vote.Token) {
		// Sanity check since proposal has already been looked up and
		// passed in to this function.
		return fmt.Errorf("invalid token %v", sv.Vote.Token)
	}

	// Validate vote bits
	for _, v := range sv.Vote.Options {
		err := validateVoteBit(sv.Vote, v.Bits)
		if err != nil {
			log.Debugf("validateStartVote: validateVoteBit '%v': %v",
				v.Id, err)
			return www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropVoteBits,
			}
		}
	}

	// Validate vote options. Only simple yes/no votes are currently
	// allowed.
	err := validateVoteOptions(sv.Vote.Options)
	if err != nil {
		return err
	}

	// Validate vote params
	switch {
	case sv.Vote.Duration < durationMin:
		// Duration not large enough
		e := fmt.Sprintf("vote duration must be >= %v", durationMin)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{e},
		}
	case sv.Vote.Duration > durationMax:
		// Duration too large
		e := fmt.Sprintf("vote duration must be <= %v", durationMax)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{e},
		}
	case sv.Vote.QuorumPercentage > 100:
		// Quorum too large
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{"quorum percentage cannot be >100"},
		}
	case sv.Vote.PassPercentage > 100:
		// Pass percentage too large
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{"pass percentage cannot be >100"},
		}
	}

	// Ensure the public key is the user's active key
	if sv.PublicKey != u.PublicKey() {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	dsv := convertStartVoteV2ToDecred(sv)
	err = dsv.VerifySignature()
	if err != nil {
		log.Debugf("validateStartVote: VerifySignature: %v", err)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Validate proposal
	votePropVersion := strconv.FormatUint(uint64(sv.Vote.ProposalVersion), 10)
	switch {
	case pr.Version != votePropVersion:
		// Vote is specifying the wrong version
		e := fmt.Sprintf("got %v, want %v", votePropVersion, pr.Version)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidProposalVersion,
			ErrorContext: []string{e},
		}
	case pr.Status != www.PropStatusPublic:
		// Proposal is not public
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongStatus,
			ErrorContext: []string{"proposal is not public"},
		}
	case vs.EndHeight != 0:
		// Vote has already started
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote already started"},
		}
	}

	return nil
}

func validateStartVoteStandard(sv www2.StartVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary, durationMin, durationMax uint32, linkByMin, linkByMax int64) error {
	err := validateStartVote(sv, u, pr, vs, durationMin, durationMax)
	if err != nil {
		return err
	}

	// The remaining validation is specific to a VoteTypeStandard.

	switch {
	case sv.Vote.Type != www2.VoteTypeStandard:
		// Not a standard vote
		e := fmt.Sprintf("vote type must be %v", www2.VoteTypeStandard)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidVoteType,
			ErrorContext: []string{e},
		}
	case vs.Status != www.PropVoteStatusAuthorized:
		// Vote has not been authorized
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote not authorized"},
		}
	case isRFPSubmission(pr):
		// The proposal is an an RFP submission. The voting period for
		// RFP submissions can only be started using the StartVoteRunoff
		// route.
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongProposalType,
			ErrorContext: []string{"cannot be an rfp submission"},
		}
	}

	// Verify the LinkBy deadline for RFP proposals. The LinkBy policy
	// requirements are enforced at the time of starting the vote
	// because their purpose is to ensure that there is enough time for
	// RFP submissions to be submitted.
	if isRFP(pr) {
		min := time.Now().Unix() + linkByMin
		max := time.Now().Unix() + linkByMax
		switch {
		case pr.LinkBy < min:
			e := fmt.Sprintf("linkby period must be at least %v seconds from "+
				"the start of the proposal vote", linkByMin)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkBy,
				ErrorContext: []string{e},
			}
		case pr.LinkBy > max:
			e := fmt.Sprintf("linkby period cannot be more than %v seconds from "+
				"the start of the proposal vote", linkByMax)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkBy,
				ErrorContext: []string{e},
			}
		}

		// If the vote durations does not use the defaults, make sure
		// that RFP submissions will have a minimum of 1 week to be
		// submitted.
		if sv.Vote.Duration != defaultVoteDurationMin {
			var (
				avgBlockTime        int64 = 300    // 5 minutes in seconds
				minSubmissionPeriod int64 = 604800 // 1 week in seconds
				duration                  = avgBlockTime * int64(sv.Vote.Duration)
				submissionPeriod          = pr.LinkBy - time.Now().Unix() - duration
			)
			if submissionPeriod < minSubmissionPeriod {
				e := fmt.Sprintf("linkby period must be at least %v seconds from "+
					"the start of the proposal vote", duration+submissionPeriod)
				return www.UserError{
					ErrorCode:    www.ErrorStatusInvalidLinkBy,
					ErrorContext: []string{e},
				}
			}
		}
	}

	return nil
}

func validateStartVoteRunoff(sv www2.StartVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary, durationMin, durationMax uint32) error {
	err := validateStartVote(sv, u, pr, vs, durationMin, durationMax)
	if err != nil {
		return err
	}

	// The remaining validation is specific to a VoteTypeRunoff.

	token := sv.Vote.Token
	switch {
	case sv.Vote.Type != www2.VoteTypeRunoff:
		// Not a runoff vote
		e := fmt.Sprintf("%v vote type must be %v",
			token, www2.VoteTypeRunoff)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidVoteType,
			ErrorContext: []string{e},
		}

	case !isRFPSubmission(pr):
		// The proposal is not an RFP submission
		e := fmt.Sprintf("%v in not an rfp submission", token)
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongProposalType,
			ErrorContext: []string{e},
		}

	case vs.Status != www.PropVoteStatusNotAuthorized:
		// Sanity check. This should not be possible.
		return fmt.Errorf("%v got vote status %v, want %v",
			token, vs.Status, www.PropVoteStatusNotAuthorized)
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

	// Fetch proposal and vote summary
	if !isTokenValid(sv.Vote.Token) {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
			ErrorContext: []string{sv.Vote.Token},
		}
	}
	pr, err := p.getProp(sv.Vote.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	vs, err := p.voteSummaryGet(sv.Vote.Token, bb)
	if err != nil {
		return nil, err
	}

	// Validate the start vote
	err = validateStartVoteStandard(sv, *u, *pr, *vs,
		p.cfg.VoteDurationMin, p.cfg.VoteDurationMax,
		p.linkByPeriodMin(), p.linkByPeriodMax())
	if err != nil {
		return nil, err
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
	log.Tracef("processStartVoteRunoffV2 %v", sv.Token)

	// Sanity check
	if !u.Admin {
		return nil, fmt.Errorf("user is not an admin")
	}

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}

	// Ensure authorize votes and start votes match
	auths := make(map[string]www2.AuthorizeVote, len(sv.AuthorizeVotes))
	starts := make(map[string]www2.StartVote, len(sv.StartVotes))
	for _, v := range sv.AuthorizeVotes {
		auths[v.Token] = v
	}
	for _, v := range sv.StartVotes {
		_, ok := auths[v.Vote.Token]
		if !ok {
			e := fmt.Sprintf("start vote found without matching authorize vote %v",
				v.Vote.Token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}
	}
	for _, v := range sv.StartVotes {
		starts[v.Vote.Token] = v
	}
	for _, v := range sv.AuthorizeVotes {
		_, ok := starts[v.Token]
		if !ok {
			e := fmt.Sprintf("authorize vote found without matching start vote %v",
				v.Token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}
	}
	if len(auths) == 0 {
		e := fmt.Sprintf("start votes and authorize votes cannot be empty")
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidRunoffVote,
			ErrorContext: []string{e},
		}
	}

	// Validate authorize votes and start votes
	for _, v := range sv.StartVotes {
		// Fetch proposal and vote summary
		token := v.Vote.Token
		if !isTokenValid(token) {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
				ErrorContext: []string{token},
			}
		}
		pr, err := p.getProp(token)
		if err != nil {
			if err == cache.ErrRecordNotFound {
				err = www.UserError{
					ErrorCode:    www.ErrorStatusProposalNotFound,
					ErrorContext: []string{token},
				}
			}
			return nil, err
		}
		vs, err := p.voteSummaryGet(token, bb)
		if err != nil {
			return nil, err
		}

		// Validate authorize vote. The validation function requires a v1
		// AuthorizeVote. This is fine. There is no difference between v1
		// and v2.
		av := auths[v.Vote.Token]
		av1 := www.AuthorizeVote{
			Token:     av.Token,
			Action:    av.Action,
			PublicKey: av.PublicKey,
			Signature: av.Signature,
		}
		err = validateAuthorizeVoteRunoff(av1, *u, *pr, *vs)
		if err != nil {
			// Attach the token to the error so the user knows which one
			// failed.
			if ue, ok := err.(*www.UserError); ok {
				ue.ErrorContext = append(ue.ErrorContext, token)
				err = ue
			}
			return nil, err
		}

		// Validate start vote
		err = validateStartVoteRunoff(v, *u, *pr, *vs,
			p.cfg.VoteDurationMin, p.cfg.VoteDurationMax)
		if err != nil {
			// Attach the token to the error so the user knows which one
			// failed.
			if ue, ok := err.(*www.UserError); ok {
				ue.ErrorContext = append(ue.ErrorContext, token)
				err = ue
			}
			return nil, err
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
	switch {
	case rfp.LinkBy > time.Now().Unix() && !p.cfg.TestNet:
		// Vote cannot start on RFP submissions until the RFP linkby
		// deadline has been met. This validation is skipped when on
		// testnet.
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusLinkByDeadlineNotMet,
		}
	case len(rfp.LinkedFrom) == 0:
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoLinkedProposals,
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
		// Filter out abandoned submissions. These are not allowed
		// to be included in a runoff vote.
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
			e := fmt.Sprintf("invalid start vote submission: %v",
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

	// Setup plugin command
	dav := convertAuthorizeVotesV2ToDecred(sv.AuthorizeVotes)
	dsv := convertStartVotesV2ToDecred(sv.StartVotes)
	payload, err := decredplugin.EncodeStartVoteRunoff(
		decredplugin.StartVoteRunoff{
			Token:          sv.Token,
			AuthorizeVotes: dav,
			StartVotes:     dsv,
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

// tokenInventory fetches the token inventory from the cache and returns a
// TokenInventoryReply. This call relies on the lazy loaded VoteResults cache
// table. If the VoteResults table is not up-to-date then this function will
// load it before retrying the token inventory call. Since politeiawww only has
// read access to the cache, loading the VoteResults table requires using a
// politeiad decredplugin command.
func (p *politeiawww) tokenInventory(bestBlock uint64, isAdmin bool) (*www.TokenInventoryReply, error) {
	var done bool
	var r www.TokenInventoryReply
	for retries := 0; !done && retries <= 1; retries++ {
		// Both vetted and unvetted tokens should be returned
		// for admins. Only vetted tokens should be returned
		// for non-admins.
		ti, err := p.decredTokenInventory(bestBlock, isAdmin)
		if err != nil {
			if err == cache.ErrRecordNotFound {
				// There are missing entries in the vote
				// results cache table. Load them.
				_, err := p.decredLoadVoteResults(bestBlock)
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

	return &r, nil
}

// processTokenInventory returns the tokens of all proposals in the inventory,
// categorized by stage of the voting process.
func (p *politeiawww) processTokenInventory(isAdmin bool) (*www.TokenInventoryReply, error) {
	log.Tracef("processTokenInventory")

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}

	return p.tokenInventory(bb, isAdmin)
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
