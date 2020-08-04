// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/decred/politeia/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/util"
)

const (
	// Blob entry data descriptors
	dataDescriptorAuthorize = "ticketvoteauthorize"
	dataDescriptorStart     = "ticketvotestart"

	// Prefixes that are appended to key-value store keys before
	// storing them in the log leaf ExtraData field.
	keyPrefixAuthorize = "ticketvoteauthorize"
	keyPrefixStart     = "ticketvotestart"
)

var (
	_ Plugin = (*ticketVotePlugin)(nil)
)

// ticketVotePlugin satsifies the Plugin interface.
type ticketVotePlugin struct {
	id      *identity.FullIdentity
	backend *tlogbe.Tlogbe
}

// authorize is the structure that is saved to disk when a vote is authorized
// or a previous authorization is revoked.
type authorize struct {
	Token     string `json:"token"`     // Record token
	Version   uint32 `json:"version"`   // Record version
	Action    string `json:"action"`    // Authorize or revoke
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Signature of token+version+action
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// start is the structure that is saved to disk when a vote is started.
//
// Signature is a signature of the SHA256 digest of the JSON encoded Vote
// struct.
type start struct {
	Vote             ticketvote.Vote `json:"vote"`
	PublicKey        string          `json:"publickey"`
	Signature        string          `json:"signature"`
	StartBlockHeight uint32          `json:"startblockheight"`
	StartBlockHash   string          `json:"startblockhash"`
	EndBlockHeight   uint32          `json:"endblockheight"`
	EligibleTickets  []string        `json:"eligibletickets"` // Ticket hashes
}

func convertTicketVoteErrFromSignatureErr(err error) ticketvote.UserError {
	var e util.SignatureError
	var s ticketvote.ErrorStatusT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = ticketvote.ErrorStatusPublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = ticketvote.ErrorStatusSignatureInvalid
		}
	}
	return ticketvote.UserError{
		ErrorCode:    s,
		ErrorContext: e.ErrorContext,
	}
}

func convertAuthorizeFromBlobEntry(be store.BlobEntry) (*authorize, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorAuthorize {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorAuthorize)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	hash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %v", err)
	}
	if !bytes.Equal(util.Digest(b), hash) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), hash)
	}
	var a authorize
	err = json.Unmarshal(b, &a)
	if err != nil {
		return nil, fmt.Errorf("unmarshal index: %v", err)
	}

	return &a, nil
}

func convertBlobEntryFromAuthorize(a authorize) (*store.BlobEntry, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorAuthorize,
		})
	if err != nil {
		return nil, err
	}
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func authorizeSave(client *tlogbe.PluginClient, a authorize) error {
	// Prepare blob
	be, err := convertBlobEntryFromAuthorize(a)
	if err != nil {
		return err
	}
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return err
	}

	// Save blob
	merkles, err := client.BlobsSave(keyPrefixAuthorize,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return fmt.Errorf("BlobsSave: %v", err)
	}
	if len(merkles) != 1 {
		return fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return nil
}

func authorizations(client *tlogbe.PluginClient) ([]authorize, error) {
	// Retrieve blobs
	blobs, err := client.BlobsByKeyPrefix(keyPrefixAuthorize)
	if err != nil {
		return nil, err
	}

	// Decode blobs
	auths := make([]authorize, 0, len(blobs))
	for _, v := range blobs {
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		a, err := convertAuthorizeFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		auths = append(auths, *a)
	}

	return auths, nil
}
func (p *ticketVotePlugin) cmdAuthorize(payload string) (string, error) {
	log.Tracef("ticketvote cmdAuthorize: %v", payload)

	// Decode payload
	a, err := ticketvote.DecodeAuthorize([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify signature
	version := strconv.FormatUint(uint64(a.Version), 10)
	msg := a.Token + version + string(a.Action)
	err = util.VerifySignature(a.Signature, a.PublicKey, msg)
	if err != nil {
		return "", convertTicketVoteErrFromSignatureErr(err)
	}

	// Get plugin client
	tokenb, err := hex.DecodeString(a.Token)
	if err != nil {
		return "", ticketvote.UserError{
			ErrorCode: ticketvote.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.PluginClient(tokenb)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", ticketvote.UserError{
				ErrorCode: ticketvote.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}
	if client.State != tlogbe.RecordStateVetted {
		return "", ticketvote.UserError{
			ErrorCode:    ticketvote.ErrorStatusRecordStateInvalid,
			ErrorContext: []string{"record not vetted"},
		}
	}

	// Verify record version
	_, err = p.backend.GetVetted(tokenb, version)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			e := fmt.Sprintf("version %v not found", version)
			return "", ticketvote.UserError{
				ErrorCode:    ticketvote.ErrorStatusRecordNotFound,
				ErrorContext: []string{e},
			}
		}
	}

	// Verify action
	switch a.Action {
	case ticketvote.ActionAuthorize:
		// This is allowed
	case ticketvote.ActionRevoke:
		// This is allowed
	default:
		return "", ticketvote.UserError{
			ErrorCode: ticketvote.ErrorStatusAuthorizeActionInvalid,
		}
	}

	// Get any previous authorizations to verify that the new action
	// is allowed based on the previous action.
	auths, err := authorizations(client)
	if err != nil {
		return "", err
	}
	var prevAction ticketvote.ActionT
	if len(auths) > 0 {
		prevAction = ticketvote.ActionT(auths[len(auths)-1].Action)
	}
	switch {
	case len(auths) == 0:
		// No previous actions. New action must be an authorize.
		if a.Action != ticketvote.ActionAuthorize {
			return "", ticketvote.UserError{
				ErrorCode:    ticketvote.ErrorStatusAuthorizeActionInvalid,
				ErrorContext: []string{"no prev action; action must be authorize"},
			}
		}
	case prevAction == ticketvote.ActionAuthorize:
		// Previous action was a authorize. This action must be revoke.
		return "", ticketvote.UserError{
			ErrorCode:    ticketvote.ErrorStatusAuthorizeActionInvalid,
			ErrorContext: []string{"prev action was authorize"},
		}
	case prevAction == ticketvote.ActionRevoke:
		// Previous action was a revoke. This action must be authorize.
		return "", ticketvote.UserError{
			ErrorCode:    ticketvote.ErrorStatusAuthorizeActionInvalid,
			ErrorContext: []string{"prev action was revoke"},
		}
	}

	// Prepare authorization
	receipt := p.id.SignMessage([]byte(a.Signature))
	auth := authorize{
		Token:     a.Token,
		Version:   a.Version,
		Action:    string(a.Action),
		PublicKey: a.PublicKey,
		Signature: a.Signature,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}

	// Save authorization
	err = authorizeSave(client, auth)
	if err != nil {
		return "", err
	}

	// Prepare reply
	ar := ticketvote.AuthorizeReply{
		Timestamp: auth.Timestamp,
		Receipt:   auth.Receipt,
	}
	reply, err := ticketvote.EncodeAuthorizeReply(ar)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *ticketVotePlugin) cmdStart(payload string) (string, error) {
	log.Tracef("ticketvote cmdStart: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdStartRunoff(payload string) (string, error) {
	log.Tracef("ticketvote cmdStartRunoff: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdBallot(payload string) (string, error) {
	log.Tracef("ticketvote cmdBallot: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdDetails(payload string) (string, error) {
	log.Tracef("ticketvote cmdDetails: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdCastVotes(payload string) (string, error) {
	log.Tracef("ticketvote cmdCastVotes: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdSummaries(payload string) (string, error) {
	log.Tracef("ticketvote cmdSummaries: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdInventory(payload string) (string, error) {
	log.Tracef("ticketvote cmdInventory: %v", payload)

	return "", nil
}

// Cmd executes a plugin command.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Cmd(cmd, payload string) (string, error) {
	log.Tracef("ticketvote Cmd: %v", cmd)

	switch cmd {
	case ticketvote.CmdAuthorize:
		return p.cmdAuthorize(payload)
	case ticketvote.CmdStart:
		return p.cmdStart(payload)
	case ticketvote.CmdStartRunoff:
		return p.cmdStartRunoff(payload)
	case ticketvote.CmdBallot:
		return p.cmdBallot(payload)
	case ticketvote.CmdDetails:
		return p.cmdDetails(payload)
	case ticketvote.CmdCastVotes:
		return p.cmdCastVotes(payload)
	case ticketvote.CmdSummaries:
		return p.cmdSummaries(payload)
	case ticketvote.CmdInventory:
		return p.cmdInventory(payload)
	}

	return "", ErrInvalidPluginCmd
}

// Hook executes a plugin hook.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Hook(h HookT, payload string) error {
	log.Tracef("ticketvote Hook: %v %v", h, payload)

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Fsck() error {
	log.Tracef("ticketvote Fsck")

	return nil
}

// Setup performs any plugin setup work that needs to be done.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Setup() error {
	log.Tracef("ticketvote Setup")

	// Ensure dcrdata plugin has been registered

	return nil
}

func TicketVotePluginNew(id *identity.FullIdentity, backend *tlogbe.Tlogbe) (*ticketVotePlugin, error) {
	return &ticketVotePlugin{
		id:      id,
		backend: backend,
	}, nil
}
