package cmsplugin

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/util"
)

type ErrorStatusT int

// Plugin settings, kinda doesn't go here but for now it is fine
const (
	Version              = "1"
	ID                   = "cms"
	CmdVoteDetails       = "votedccdetails"
	CmdStartVote         = "startdccvote"
	CmdCastVote          = "castdccvote"
	CmdInventory         = "cmsinventory"
	CmdVoteSummary       = "votedccsummary"
	CmdDCCVoteResults    = "dccvoteresults"
	MDStreamVoteBits     = 16 // Vote bits and mask
	MDStreamVoteSnapshot = 17 // Vote tickets and start/end parameters

	VoteDurationMin = 2016 // Minimum vote duration (in blocks)
	VoteDurationMax = 4032 // Maximum vote duration (in blocks)

	// Error status codes
	ErrorStatusInvalid          ErrorStatusT = 0
	ErrorStatusInternalError    ErrorStatusT = 1
	ErrorStatusDCCNotFound      ErrorStatusT = 2
	ErrorStatusInvalidVoteBit   ErrorStatusT = 3
	ErrorStatusVoteHasEnded     ErrorStatusT = 4
	ErrorStatusDuplicateVote    ErrorStatusT = 5
	ErrorStatusIneligibleUserID ErrorStatusT = 6

	// String constant to ensure that the observed dcc vote option is tabulated
	// as "approved" or "disapproved".
	DCCApprovalString    = "yes"
	DCCDisapprovalString = "no"
)

var (
	// ErrorStatus converts error status codes to human readable text.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:          "invalid error status",
		ErrorStatusInternalError:    "internal error",
		ErrorStatusDCCNotFound:      "dcc not found",
		ErrorStatusInvalidVoteBit:   "invalid vote bit",
		ErrorStatusVoteHasEnded:     "vote has ended",
		ErrorStatusDuplicateVote:    "duplicate vote",
		ErrorStatusIneligibleUserID: "inegligible user id",
	}
)

// VoteOption describes a single vote option.
type VoteOption struct {
	Id          string `json:"id"`          // Single unique word identifying vote (e.g. yes)
	Description string `json:"description"` // Longer description of the vote.
	Bits        uint64 `json:"bits"`        // Bits used for this option
}

// Vote represents the vote options for vote that is identified by its token.
type Vote struct {
	Token            string       `json:"token"`            // Token that identifies vote
	Mask             uint64       `json:"mask"`             // Valid votebits
	Duration         uint32       `json:"duration"`         // Duration in blocks
	QuorumPercentage uint32       `json:"quorumpercentage"` // Percent of eligible votes required for quorum
	PassPercentage   uint32       `json:"passpercentage"`   // Percent of total votes required to pass
	Options          []VoteOption `json:"options"`          // Vote option
}

// EncodeVote encodes Vote into a JSON byte slice.
func EncodeVote(v Vote) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVote decodes a JSON byte slice into a Vote.
func DecodeVote(payload []byte) (*Vote, error) {
	var v Vote

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// CastVote is a signed vote.
type CastVote struct {
	Token     string `json:"token"`     // DCC ID
	UserID    string `json:"publickey"` // User ID provided by cmswww
	VoteBit   string `json:"votebit"`   // Vote bit that was selected, this is encode in hex
	Signature string `json:"signature"` // Signature of the Token+VoteBit+UserID by the submitting user.
}

// EncodeCastVote encodes CastVotes into a JSON byte slice.
func EncodeCastVote(cv CastVote) ([]byte, error) {
	return json.Marshal(cv)
}

// DecodeCastVote decodes a JSON byte slice into a CastVote.
func DecodeCastVote(payload []byte) (*CastVote, error) {
	var cv CastVote

	err := json.Unmarshal(payload, &cv)
	if err != nil {
		return nil, err
	}

	return &cv, nil
}

// CastVoteReply contains the signature or error to a cast vote command. The
// Error and ErrorStatus fields will only be populated if something went wrong
// while attempting to cast the vote.
type CastVoteReply struct {
	ClientSignature string       `json:"clientsignature"`       // Signature that was sent in
	Signature       string       `json:"signature"`             // Signature of the ClientSignature
	Error           string       `json:"error"`                 // Error status message
	ErrorStatus     ErrorStatusT `json:"errorstatus,omitempty"` // Error status code
}

// EncodeCastVoteReply encodes CastVoteReply into a JSON byte slice.
func EncodeCastVoteReply(cvr CastVoteReply) ([]byte, error) {
	return json.Marshal(cvr)
}

// DecodeCastVoteReply decodes a JSON byte slice into a CastVote.
func DecodeCastVoteReply(payload []byte) (*CastVoteReply, error) {
	var cvr CastVoteReply

	err := json.Unmarshal(payload, &cvr)
	if err != nil {
		return nil, err
	}

	return &cvr, nil
}

// UserWeight describes a single vote option.
type UserWeight struct {
	UserID string `json:"userid"` // Unique user id from cmswww.
	Weight int64  `json:"weight"` // Calculated user voted weight, provided by cmswww.
}

const VersionStartVote = 1

// StartVote instructs the plugin to commence voting on a proposal with the
// provided vote bits.
type StartVote struct {
	// decred plugin only data
	Version uint   `json:"version"` // Version of this structure
	Token   string `json:"token"`   // Token

	PublicKey   string       `json:"publickey"`   // Key used for signature.
	UserWeights []UserWeight `json:"userweights"` // Array of User ID + weight
	Vote        Vote         `json:"vote"`        // Vote + options
	Signature   string       `json:"signature"`   // Signature of Votehash
}

// EncodeStartVote a JSON byte slice.
func EncodeStartVote(v StartVote) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeStartVote a JSON byte slice into a StartVote.
func DecodeStartVote(payload []byte) (StartVote, error) {
	var sv StartVote

	err := json.Unmarshal(payload, &sv)
	if err != nil {
		return sv, err
	}

	return sv, nil
}

const VersionStartVoteReply = 1

// StartVoteReply is the reply to StartVote.
type StartVoteReply struct {
	// cms plugin only data
	Version uint `json:"version"` // Version of this structure

	// Shared data
	StartBlockHeight uint32 `json:"startblockheight"` // Block height
	StartBlockHash   string `json:"startblockhash"`   // Block hash
	EndHeight        uint32 `json:"endheight"`        // Height of vote end
}

// EncodeStartVoteReply encodes StartVoteReply into a JSON byte slice.
func EncodeStartVoteReply(v StartVoteReply) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeStartVoteReply decodes a JSON byte slice into a StartVoteReply.
func DecodeStartVoteReply(payload []byte) (StartVoteReply, error) {
	var v StartVoteReply

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return v, err
	}

	return v, nil
}

// VoteDetails is used to retrieve the voting period details for a record.
type VoteDetails struct {
	Token string `json:"token"` // Censorship token
}

// EncodeVoteDetails encodes VoteDetails into a JSON byte slice.
func EncodeVoteDetails(vd VoteDetails) ([]byte, error) {
	return json.Marshal(vd)
}

// DecodeVoteDetails decodes a JSON byte slice into a VoteDetails.
func DecodeVoteDetails(payload []byte) (*VoteDetails, error) {
	var vd VoteDetails

	err := json.Unmarshal(payload, &vd)
	if err != nil {
		return nil, err
	}

	return &vd, nil
}

// VoteDetailsReply is the reply to VoteDetails.
type VoteDetailsReply struct {
	StartVote      StartVote      `json:"startvote"`      // Vote ballot
	StartVoteReply StartVoteReply `json:"startvotereply"` // Start vote snapshot
}

// EncodeVoteDetailsReply encodes VoteDetailsReply into a JSON byte slice.
func EncodeVoteDetailsReply(vdr VoteDetailsReply) ([]byte, error) {
	return json.Marshal(vdr)
}

// DecodeVoteReply decodes a JSON byte slice into a VoteDetailsReply.
func DecodeVoteDetailsReply(payload []byte) (*VoteDetailsReply, error) {
	var vdr VoteDetailsReply

	err := json.Unmarshal(payload, &vdr)
	if err != nil {
		return nil, err
	}

	return &vdr, nil
}

type VoteResults struct {
	Token string `json:"token"` // Censorship token
}

type VoteResultsReply struct {
	StartVote StartVote  `json:"startvote"` // Original ballot
	CastVotes []CastVote `json:"castvotes"` // All votes
}

// EncodeVoteResults encodes VoteResults into a JSON byte slice.
func EncodeVoteResults(v VoteResults) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteResults decodes a JSON byte slice into a VoteResults.
func DecodeVoteResults(payload []byte) (*VoteResults, error) {
	var v VoteResults

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// EncodeVoteResultsReply encodes VoteResults into a JSON byte slice.
func EncodeVoteResultsReply(v VoteResultsReply) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteResultsReply decodes a JSON byte slice into a VoteResults.
func DecodeVoteResultsReply(payload []byte) (*VoteResultsReply, error) {
	var v VoteResultsReply

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// VoteSummary requests a summary of a proposal vote. This includes certain
// voting period parameters and a summary of the vote results.
type VoteSummary struct {
	Token string `json:"token"` // Censorship token
}

// EncodeVoteSummary encodes VoteSummary into a JSON byte slice.
func EncodeVoteSummary(v VoteSummary) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteSummary decodes a JSON byte slice into a VoteSummary.
func DecodeVoteSummary(payload []byte) (*VoteSummary, error) {
	var v VoteSummary

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// VoteOptionResult describes a vote option and the total number of votes that
// have been cast for this option.
type VoteOptionResult struct {
	ID          string `json:"id"`          // Single unique word identifying vote (e.g. yes)
	Description string `json:"description"` // Longer description of the vote.
	Bits        uint64 `json:"bits"`        // Bits used for this option
	Votes       uint64 `json:"votes"`       // Number of votes cast for this option
}

// VoteSummaryReply is the reply to the VoteSummary command and returns certain
// voting period parameters as well as a summary of the vote results.
type VoteSummaryReply struct {
	Duration       uint32             `json:"duration"`       // Vote duration
	EndHeight      uint32             `json:"endheight"`      // End block height
	PassPercentage uint32             `json:"passpercentage"` // Percent of total votes required to pass
	Results        []VoteOptionResult `json:"results"`        // Vote results
}

// EncodeVoteSummaryReply encodes VoteSummary into a JSON byte slice.
func EncodeVoteSummaryReply(v VoteSummaryReply) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteSummaryReply decodes a JSON byte slice into a VoteSummaryReply.
func DecodeVoteSummaryReply(payload []byte) (*VoteSummaryReply, error) {
	var v VoteSummaryReply

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// Inventory is used to retrieve the decred plugin inventory.
type Inventory struct{}

// EncodeInventory encodes Inventory into a JSON byte slice.
func EncodeInventory(i Inventory) ([]byte, error) {
	return json.Marshal(i)
}

// DecodeInventory decodes a JSON byte slice into a Inventory.
func DecodeInventory(payload []byte) (*Inventory, error) {
	var i Inventory

	err := json.Unmarshal(payload, &i)
	if err != nil {
		return nil, err
	}

	return &i, nil
}

// StartVoteTuple is used to return the StartVote and StartVoteReply for a
// record. StartVoteReply does not contain any record identifying data so it
// must be returned with the StartVote in order to know what record it belongs
// to.
type StartVoteTuple struct {
	StartVote      StartVote      `json:"startvote"`      // Start vote
	StartVoteReply StartVoteReply `json:"startvotereply"` // Start vote reply
}

// InventoryReply returns the cms plugin inventory.
type InventoryReply struct {
	StartVoteTuples []StartVoteTuple `json:"startvotetuples"` // Start vote tuples
	CastVotes       []CastVote       `json:"castvotes"`       // Cast votes
}

// EncodeInventoryReply encodes a InventoryReply into a JSON byte slice.
func EncodeInventoryReply(ir InventoryReply) ([]byte, error) {
	return json.Marshal(ir)
}

// DecodeInventoryReply decodes a JSON byte slice into a inventory.
func DecodeInventoryReply(payload []byte) (*InventoryReply, error) {
	var ir InventoryReply

	err := json.Unmarshal(payload, &ir)
	if err != nil {
		return nil, err
	}

	return &ir, nil
}

// LoadVoteResults creates a vote results entry in the cache for any proposals
// that have finsished voting but have not yet been added to the lazy loaded
// vote results table.
type LoadVoteResults struct {
	BestBlock uint64 `json:"bestblock"` // Best block height
}

// EncodeLoadVoteResults encodes a LoadVoteResults into a JSON byte slice.
func EncodeLoadVoteResults(lvr LoadVoteResults) ([]byte, error) {
	return json.Marshal(lvr)
}

// DecodeLoadVoteResults decodes a JSON byte slice into a LoadVoteResults.
func DecodeLoadVoteResults(payload []byte) (*LoadVoteResults, error) {
	var lvr LoadVoteResults

	err := json.Unmarshal(payload, &lvr)
	if err != nil {
		return nil, err
	}

	return &lvr, nil
}

// LoadVoteResultsReply is the reply to the LoadVoteResults command.
type LoadVoteResultsReply struct{}

// EncodeLoadVoteResultsReply encodes a LoadVoteResultsReply into a JSON
// byte slice.
func EncodeLoadVoteResultsReply(reply LoadVoteResultsReply) ([]byte, error) {
	return json.Marshal(reply)
}

// DecodeLoadVoteResultsReply decodes a JSON byte slice into a LoadVoteResults.
func DecodeLoadVoteResultsReply(payload []byte) (*LoadVoteResultsReply, error) {
	var reply LoadVoteResultsReply

	err := json.Unmarshal(payload, &reply)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// VerifySignature verifies that the StartVoteV2 signature is correct.
func (s *StartVote) VerifySignature() error {
	sig, err := util.ConvertSignature(s.Signature)
	if err != nil {
		return err
	}
	b, err := hex.DecodeString(s.PublicKey)
	if err != nil {
		return err
	}
	pk, err := identity.PublicIdentityFromBytes(b)
	if err != nil {
		return err
	}
	vb, err := json.Marshal(s.Vote)
	if err != nil {
		return err
	}
	msg := hex.EncodeToString(util.Digest(vb))
	if !pk.VerifyMessage([]byte(msg), sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}
