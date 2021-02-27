// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package records

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

func (r *Records) processNew(ctx context.Context, n v1.New, u user.User) (*v1.NewReply, error) {
	log.Tracef("processNew: %v", u.Username)

	// Verify user signed using active identity
	if u.PublicKey() != n.PublicKey {
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Execute pre plugin hooks. Checking the mode is a temporary
	// measure until user plugins have been properly implemented.
	switch r.cfg.Mode {
	case config.PoliteiaWWWMode:
		err := r.piHookNewRecordPre(u)
		if err != nil {
			return nil, err
		}
	}

	// Setup metadata stream
	um := usermd.UserMetadata{
		UserID:    u.ID.String(),
		PublicKey: n.PublicKey,
		Signature: n.Signature,
	}
	b, err := json.Marshal(um)
	if err != nil {
		return nil, err
	}
	metadata := []pdv1.MetadataStream{
		{
			PluginID: usermd.PluginID,
			ID:       usermd.MDStreamIDUserMetadata,
			Payload:  string(b),
		},
	}

	// Save record to politeiad
	f := convertFilesToPD(n.Files)
	cr, err := r.politeiad.NewRecord(ctx, metadata, f)
	if err != nil {
		return nil, err
	}

	// Get full record
	rc, err := r.record(ctx, v1.RecordStateUnvetted, cr.Token, "")
	if err != nil {
		return nil, err
	}

	log.Infof("Record submitted: %v", rc.CensorshipRecord.Token)
	for k, f := range rc.Files {
		log.Infof("%02v: %v", k, f.Name)
	}

	// Execute post plugin hooks. Checking the mode is a temporary
	// measure until user plugins have been properly implemented.
	switch r.cfg.Mode {
	case config.PoliteiaWWWMode:
		err := r.piHookNewRecordPost(u, rc.CensorshipRecord.Token)
		if err != nil {
			return nil, err
		}
	}

	// Emit event
	r.events.Emit(EventTypeNew,
		EventNew{
			User:   u,
			Record: *rc,
		})

	return &v1.NewReply{
		Record: *rc,
	}, nil
}

// filesToDel returns the names of the files that are included in the current
// files but are not included in updated files. These are the files that need
// to be deleted from a record on update.
func filesToDel(current []pdv1.File, updated []pdv1.File) []string {
	curr := make(map[string]struct{}, len(current)) // [name]struct
	for _, v := range updated {
		curr[v.Name] = struct{}{}
	}

	del := make([]string, 0, len(current))
	for _, v := range current {
		_, ok := curr[v.Name]
		if !ok {
			del = append(del, v.Name)
		}
	}

	return del
}

func (r *Records) processEdit(ctx context.Context, e v1.Edit, u user.User) (*v1.EditReply, error) {
	log.Tracef("processEdit: %v %v", e.Token, u.Username)

	// Verify user signed using active identity
	if u.PublicKey() != e.PublicKey {
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Get current record
	var (
		curr *pdv1.Record
		err  error
	)
	switch e.State {
	case v1.RecordStateUnvetted:
		curr, err = r.politeiad.GetUnvetted(ctx, e.Token, "")
		if err != nil {
			return nil, err
		}
	case v1.RecordStateVetted:
		curr, err = r.politeiad.GetVetted(ctx, e.Token, "")
		if err != nil {
			return nil, err
		}
	default:
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodeRecordStateInvalid,
		}
	}

	// Setup files
	filesAdd := convertFilesToPD(e.Files)
	filesDel := filesToDel(curr.Files, filesAdd)

	// Setup metadata
	um := usermd.UserMetadata{
		UserID:    u.ID.String(),
		PublicKey: e.PublicKey,
		Signature: e.Signature,
	}
	b, err := json.Marshal(um)
	if err != nil {
		return nil, err
	}
	mdOverwrite := []pdv1.MetadataStream{
		{
			PluginID: usermd.PluginID,
			ID:       usermd.MDStreamIDUserMetadata,
			Payload:  string(b),
		},
	}
	mdAppend := []pdv1.MetadataStream{}

	// Save update to politeiad
	var pdr *pdv1.Record
	switch e.State {
	case v1.RecordStateUnvetted:
		pdr, err = r.politeiad.UpdateUnvetted(ctx, e.Token, mdAppend,
			mdOverwrite, filesAdd, filesDel)
		if err != nil {
			return nil, err
		}
	case v1.RecordStateVetted:
		pdr, err = r.politeiad.UpdateVetted(ctx, e.Token, mdAppend,
			mdOverwrite, filesAdd, filesDel)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid state %v", e.State)
	}

	rc := convertRecordToV1(*pdr, e.State)
	recordPopulateUserData(&rc, u)

	log.Infof("Record edited: %v %v", e.State, rc.CensorshipRecord.Token)
	for k, f := range rc.Files {
		log.Infof("%02v: %v", k, f.Name)
	}

	// Emit event
	r.events.Emit(EventTypeEdit,
		EventEdit{
			User:   u,
			State:  e.State,
			Record: rc,
		})

	return &v1.EditReply{
		Record: rc,
	}, nil
}

func (r *Records) processSetStatus(ctx context.Context, ss v1.SetStatus, u user.User) (*v1.SetStatusReply, error) {
	log.Tracef("processSetStatus: %v %v %v", ss.Token, ss.Status, ss.Reason)

	// Verify user signed using active identity
	if u.PublicKey() != ss.PublicKey {
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Setup status change metadata
	scm := usermd.StatusChangeMetadata{
		Token:     ss.Token,
		Version:   ss.Version,
		Status:    uint32(ss.Status),
		Reason:    ss.Reason,
		PublicKey: ss.PublicKey,
		Signature: ss.Signature,
		Timestamp: time.Now().Unix(),
	}
	b, err := json.Marshal(scm)
	if err != nil {
		return nil, err
	}
	mdAppend := []pdv1.MetadataStream{
		{
			PluginID: usermd.PluginID,
			ID:       usermd.MDStreamIDStatusChanges,
			Payload:  string(b),
		},
	}
	mdOverwrite := []pdv1.MetadataStream{}

	// Send politeiad request
	var (
		s   = convertStatusToPD(ss.Status)
		pdr *pdv1.Record
	)
	switch ss.State {
	case v1.RecordStateUnvetted:
		pdr, err = r.politeiad.SetUnvettedStatus(ctx, ss.Token,
			s, mdAppend, mdOverwrite)
		if err != nil {
			return nil, err
		}
	case v1.RecordStateVetted:
		pdr, err = r.politeiad.SetVettedStatus(ctx, ss.Token,
			s, mdAppend, mdOverwrite)
		if err != nil {
			return nil, err
		}
	default:
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodeRecordStateInvalid,
		}
	}

	// Convert the record. The state may need to be updated if the
	// record was made public.
	var state string
	switch ss.Status {
	case v1.RecordStatusPublic:
		// Flip state from unvetted to vetted
		state = pdv1.RecordStateVetted
	default:
		state = ss.State
	}
	rc := convertRecordToV1(*pdr, state)
	recordPopulateUserData(&rc, u)

	// Emit event
	r.events.Emit(EventTypeSetStatus,
		EventSetStatus{
			State:  state,
			Record: rc,
		})

	return &v1.SetStatusReply{
		Record: rc,
	}, nil
}

// record returns a version of a record from politeiad. If version is an empty
// string then the most recent version will be returned.
func (r *Records) record(ctx context.Context, state, token, version string) (*v1.Record, error) {
	var (
		pdr *pdv1.Record
		err error
	)
	switch state {
	case v1.RecordStateUnvetted:
		pdr, err = r.politeiad.GetUnvetted(ctx, token, version)
		if err != nil {
			return nil, err
		}
	case v1.RecordStateVetted:
		pdr, err = r.politeiad.GetVetted(ctx, token, version)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid state %v", state)
	}

	rc := convertRecordToV1(*pdr, state)

	// Fill in user data
	userID := userIDFromMetadataStreams(rc.Metadata)
	uid, err := uuid.Parse(userID)
	u, err := r.userdb.UserGetById(uid)
	if err != nil {
		return nil, err
	}
	recordPopulateUserData(&rc, *u)

	return &rc, nil
}

func (r *Records) processDetails(ctx context.Context, d v1.Details, u *user.User) (*v1.DetailsReply, error) {
	log.Tracef("processDetails: %v %v %v", d.State, d.Token, d.Version)

	// Verify state
	switch d.State {
	case v1.RecordStateUnvetted, v1.RecordStateVetted:
		// Allowed; continue
	default:
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodeRecordStateInvalid,
		}
	}

	// Get record
	rc, err := r.record(ctx, d.State, d.Token, d.Version)
	if err != nil {
		return nil, err
	}

	// Only admins and the record author are allowed to retrieve
	// unvetted record files. Remove files if the user is not an admin
	// or the author. This is a public route so a user may not be
	// present.
	if d.State == v1.RecordStateUnvetted {
		var (
			authorID = userIDFromMetadataStreams(rc.Metadata)
			isAuthor = u != nil && u.ID.String() == authorID
			isAdmin  = u != nil && u.Admin
		)
		if !isAuthor && !isAdmin {
			rc.Files = []v1.File{}
		}
	}

	return &v1.DetailsReply{
		Record: *rc,
	}, nil
}

func (r *Records) processRecords(ctx context.Context, rs v1.Records, u *user.User) (*v1.RecordsReply, error) {
	log.Tracef("processRecords: %v %v", rs.State, len(rs.Tokens))

	// Verify state
	switch rs.State {
	case v1.RecordStateUnvetted, v1.RecordStateVetted:
		// Allowed; continue
	default:
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodeRecordStateInvalid,
		}
	}

	// Verify page size
	if len(rs.Tokens) > v1.RecordsPageSize {
		e := fmt.Sprintf("max page size is %v", v1.RecordsPageSize)
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePageSizeExceeded,
			ErrorContext: e,
		}
	}

	// Get all records in the batch. This should be a batched call to
	// politeiad, but the politeiad API does not provided a batched
	// records endpoint.
	records := make(map[string]v1.Record, len(rs.Tokens))
	for _, v := range rs.Tokens {
		rc, err := r.record(ctx, rs.State, v, "")
		if err != nil {
			// If any error occured simply skip this record. It will not
			// be included in the reply.
			continue
		}

		// Record files are not returned in this call
		rc.Files = []v1.File{}

		records[rc.CensorshipRecord.Token] = *rc
	}

	return &v1.RecordsReply{
		Records: records,
	}, nil
}

func (r *Records) processInventory(ctx context.Context, i v1.Inventory, u *user.User) (*v1.InventoryReply, error) {
	log.Tracef("processInventory: %v %v %v", i.State, i.Status, i.Page)

	// The inventory arguments are optional. If a status is provided
	// then they all arguments must be provided.
	var s pdv1.RecordStatusT
	if i.Status != v1.RecordStatusInvalid {
		// Verify state
		switch i.State {
		case v1.RecordStateUnvetted, v1.RecordStateVetted:
			// Allowed; continue
		default:
			return nil, v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeRecordStateInvalid,
			}
		}

		// Verify status
		s = convertStatusToPD(i.Status)
		if s == pdv1.RecordStatusInvalid {
			return nil, v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeRecordStatusInvalid,
			}
		}
	}

	// Get inventory
	ir, err := r.politeiad.InventoryByStatus(ctx, i.State, s, i.Page)
	if err != nil {
		return nil, err
	}

	unvetted := make(map[string][]string, len(ir.Unvetted))
	vetted := make(map[string][]string, len(ir.Vetted))
	for k, v := range ir.Vetted {
		ks := v1.RecordStatuses[convertStatusToV1(k)]
		vetted[ks] = v
	}

	// Only admins are allowed to retrieve unvetted tokens. A user may
	// or may not exist.
	if u != nil && u.Admin {
		for k, v := range ir.Unvetted {
			ks := v1.RecordStatuses[convertStatusToV1(k)]
			unvetted[ks] = v
		}
	}

	return &v1.InventoryReply{
		Unvetted: unvetted,
		Vetted:   vetted,
	}, nil
}

func (r *Records) processTimestamps(ctx context.Context, t v1.Timestamps, isAdmin bool) (*v1.TimestampsReply, error) {
	log.Tracef("processTimestamps: %v %v %v", t.State, t.Token, t.Version)

	// Get record timestamps
	var (
		rt  *pdv1.RecordTimestamps
		err error
	)
	switch t.State {
	case v1.RecordStateUnvetted:
		rt, err = r.politeiad.GetUnvettedTimestamps(ctx, t.Token, t.Version)
		if err != nil {
			return nil, err
		}
	case v1.RecordStateVetted:
		rt, err = r.politeiad.GetVettedTimestamps(ctx, t.Token, t.Version)
		if err != nil {
			return nil, err
		}
	default:
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodeRecordStateInvalid,
		}
	}

	var (
		recordMD = convertTimestampToV1(rt.RecordMetadata)
		metadata = make(map[string]v1.Timestamp, len(rt.Files))
		files    = make(map[string]v1.Timestamp, len(rt.Files))
	)
	for k, v := range rt.Metadata {
		metadata[k] = convertTimestampToV1(v)
	}
	for k, v := range rt.Files {
		files[k] = convertTimestampToV1(v)
	}

	// Unvetted data blobs are stripped if the user is not an admin.
	// The rest of the timestamp is still returned.
	if t.State == v1.RecordStateUnvetted && !isAdmin {
		recordMD.Data = ""
		for k, v := range files {
			v.Data = ""
			files[k] = v
		}
		for k, v := range metadata {
			v.Data = ""
			metadata[k] = v
		}
	}

	return &v1.TimestampsReply{
		RecordMetadata: recordMD,
		Files:          files,
		Metadata:       metadata,
	}, nil
}

func (r *Records) processUserRecords(ctx context.Context, ur v1.UserRecords, u *user.User) (*v1.UserRecordsReply, error) {
	log.Tracef("processUserRecords: %v", ur.UserID)

	reply, err := r.politeiad.UserRecords(ctx, ur.UserID)
	if err != nil {
		return nil, err
	}

	// Unpack reply
	var (
		unvetted = make([]string, 0)
		vetted   = make([]string, 0)
	)
	tokens, ok := reply[v1.RecordStateUnvetted]
	if ok {
		unvetted = tokens
	}
	tokens, ok = reply[v1.RecordStateVetted]
	if ok {
		vetted = tokens
	}

	// Determine if unvetted tokens should be returned
	switch {
	case u == nil:
		// No user session. Remove unvetted.
		unvetted = []string{}
	case u.Admin:
		// User is an admin. Return unvetted.
	case ur.UserID == u.ID.String():
		// User is requesting their own records. Return unvetted.
	default:
		// Remove unvetted for all other cases
		unvetted = []string{}
	}

	return &v1.UserRecordsReply{
		Unvetted: unvetted,
		Vetted:   vetted,
	}, nil
}

// recordPopulateUserData populates the record with user data that is not
// stored in politeiad.
func recordPopulateUserData(r *v1.Record, u user.User) {
	r.Username = u.Username
}

// userMetadataDecode decodes and returns the UserMetadata from the provided
// metadata streams. If a UserMetadata is not found, nil is returned.
func userMetadataDecode(ms []v1.MetadataStream) (*usermd.UserMetadata, error) {
	var userMD *usermd.UserMetadata
	for _, v := range ms {
		if v.PluginID != usermd.PluginID ||
			v.ID != usermd.MDStreamIDUserMetadata {
			// Not the mdstream we're looking for
			continue
		}
		var um usermd.UserMetadata
		err := json.Unmarshal([]byte(v.Payload), &um)
		if err != nil {
			return nil, err
		}
		userMD = &um
		break
	}
	return userMD, nil
}

// userIDFromMetadataStreams searches for a UserMetadata and parses the user ID
// from it if found. An empty string is returned if no UserMetadata is found.
func userIDFromMetadataStreams(ms []v1.MetadataStream) string {
	um, err := userMetadataDecode(ms)
	if err != nil {
		return ""
	}
	if um == nil {
		return ""
	}
	return um.UserID
}

func convertFilesToPD(f []v1.File) []pdv1.File {
	files := make([]pdv1.File, 0, len(f))
	for _, v := range f {
		files = append(files, pdv1.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}
	return files
}

func convertStatusToPD(s v1.RecordStatusT) pdv1.RecordStatusT {
	switch s {
	case v1.RecordStatusUnreviewed:
		return pdv1.RecordStatusNotReviewed
	case v1.RecordStatusPublic:
		return pdv1.RecordStatusPublic
	case v1.RecordStatusCensored:
		return pdv1.RecordStatusCensored
	case v1.RecordStatusArchived:
		return pdv1.RecordStatusArchived
	}
	return pdv1.RecordStatusInvalid
}

func convertStatusToV1(s pdv1.RecordStatusT) v1.RecordStatusT {
	switch s {
	case pdv1.RecordStatusNotReviewed:
		return v1.RecordStatusUnreviewed
	case pdv1.RecordStatusPublic:
		return v1.RecordStatusPublic
	case pdv1.RecordStatusCensored:
		return v1.RecordStatusCensored
	case pdv1.RecordStatusArchived:
		return v1.RecordStatusArchived
	}
	return v1.RecordStatusInvalid
}

func convertFilesToV1(f []pdv1.File) []v1.File {
	files := make([]v1.File, 0, len(f))
	for _, v := range f {
		files = append(files, v1.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}
	return files
}

func convertMetadataStreamsToV1(ms []pdv1.MetadataStream) []v1.MetadataStream {
	metadata := make([]v1.MetadataStream, 0, len(ms))
	for _, v := range ms {
		metadata = append(metadata, v1.MetadataStream{
			PluginID: v.PluginID,
			ID:       v.ID,
			Payload:  v.Payload,
		})
	}
	return metadata
}

func convertCensorshipRecordToV1(cr pdv1.CensorshipRecord) v1.CensorshipRecord {
	return v1.CensorshipRecord{
		Token:     cr.Token,
		Merkle:    cr.Merkle,
		Signature: cr.Signature,
	}
}

func convertRecordToV1(r pdv1.Record, state string) v1.Record {
	// User fields that are not part of the politeiad record have
	// been intentionally left blank. These fields must be pulled
	// from the user database.
	return v1.Record{
		State:            state,
		Status:           convertStatusToV1(r.Status),
		Version:          r.Version,
		Timestamp:        r.Timestamp,
		Username:         "", // Intentionally left blank
		Metadata:         convertMetadataStreamsToV1(r.Metadata),
		Files:            convertFilesToV1(r.Files),
		CensorshipRecord: convertCensorshipRecordToV1(r.CensorshipRecord),
	}
}

func convertProofToV1(p pdv1.Proof) v1.Proof {
	return v1.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestampToV1(t pdv1.Timestamp) v1.Timestamp {
	proofs := make([]v1.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertProofToV1(v))
	}
	return v1.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}
