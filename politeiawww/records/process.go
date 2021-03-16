// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package records

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
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
	metadata := []pdv2.MetadataStream{
		{
			PluginID: usermd.PluginID,
			StreamID: usermd.StreamIDUserMetadata,
			Payload:  string(b),
		},
	}

	// Save record to politeiad
	f := convertFilesToPD(n.Files)
	pdr, err := r.politeiad.RecordNew(ctx, metadata, f)
	if err != nil {
		return nil, err
	}
	rc, err := r.convertRecordToV1(*pdr)
	if err != nil {
		return nil, err
	}

	log.Infof("Record submitted: %v", rc.CensorshipRecord.Token)
	for k, f := range rc.Files {
		log.Debugf("%02v: %v", k, f.Name)
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
func filesToDel(current []v1.File, updated []v1.File) []string {
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
	curr, err := r.record(ctx, e.Token, 0)
	if err != nil {
		if err == errRecordNotFound {
			return nil, v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeRecordNotFound,
			}
		}
		return nil, err
	}

	// Setup files
	filesAdd := convertFilesToPD(e.Files)
	filesDel := filesToDel(curr.Files, e.Files)

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
	mdOverwrite := []pdv2.MetadataStream{
		{
			PluginID: usermd.PluginID,
			StreamID: usermd.StreamIDUserMetadata,
			Payload:  string(b),
		},
	}
	mdAppend := []pdv2.MetadataStream{}

	// Save update to politeiad
	pdr, err := r.politeiad.RecordEdit(ctx, e.Token, mdAppend,
		mdOverwrite, filesAdd, filesDel)
	if err != nil {
		return nil, err
	}
	rc := convertRecordToV1(*pdr)
	recordPopulateUserData(&rc, u)

	log.Infof("Record edited: %v", rc.CensorshipRecord.Token)
	for k, f := range rc.Files {
		log.Debugf("%02v: %v", k, f.Name)
	}

	// Emit event
	r.events.Emit(EventTypeEdit,
		EventEdit{
			User:   u,
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
	mdAppend := []pdv2.MetadataStream{
		{
			PluginID: usermd.PluginID,
			StreamID: usermd.StreamIDStatusChanges,
			Payload:  string(b),
		},
	}
	mdOverwrite := []pdv2.MetadataStream{}

	// Send politeiad request
	s := convertStatusToPD(ss.Status)
	pdr, err := r.politeiad.RecordSetStatus(ctx, ss.Token, s,
		mdAppend, mdOverwrite)
	if err != nil {
		return nil, err
	}
	rc := convertRecordToV1(*pdr)
	recordPopulateUserData(&rc, u)

	// Emit event
	r.events.Emit(EventTypeSetStatus,
		EventSetStatus{
			Record: rc,
		})

	return &v1.SetStatusReply{
		Record: rc,
	}, nil
}

func (r *Records) processDetails(ctx context.Context, d v1.Details, u *user.User) (*v1.DetailsReply, error) {
	log.Tracef("processDetails: %v %v", d.Token, d.Version)

	// Get record
	rc, err := r.record(ctx, d.Token, d.Version)
	if err != nil {
		if err == errRecordNotFound {
			return nil, v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeRecordNotFound,
			}
		}
	}

	// Only admins and the record author are allowed to retrieve
	// unvetted record files. Remove files if the user is not an admin
	// or the author. This is a public route so a user may not be
	// present.
	if rc.State == v1.RecordStateUnvetted {
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
	log.Tracef("processRecords: %v reqs", len(rs.Requests))

	// Verify page size
	if len(rs.Requests) > v1.RecordsPageSize {
		e := fmt.Sprintf("max page size is %v", v1.RecordsPageSize)
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePageSizeExceeded,
			ErrorContext: e,
		}
	}

	// Get records
	reqs := convertRequestsToPD(rs.Requests)
	records, err := r.records(ctx, reqs)
	if err != nil {
		return nil, err
	}

	return &v1.RecordsReply{
		Records: records,
	}, nil
}

func (r *Records) processInventory(ctx context.Context, i v1.Inventory, u *user.User) (*v1.InventoryReply, error) {
	log.Tracef("processInventory: %v %v %v", i.State, i.Status, i.Page)

	// The inventory arguments are optional. If a status is provided
	// then they all arguments must be provided.
	var (
		state  pdv2.RecordStateT
		status pdv2.RecordStatusT
	)
	if i.Status != v1.RecordStatusInvalid {
		// Verify state
		state = convertStateToPD(i.State)
		if state == pdv2.RecordStateInvalid {
			return nil, v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeRecordStateInvalid,
			}
		}

		// Verify status
		status = convertStatusToPD(i.Status)
		if status == pdv2.RecordStatusInvalid {
			return nil, v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeRecordStatusInvalid,
			}
		}
	}

	// Get inventory
	ir, err := r.politeiad.Inventory(ctx, state, status, i.Page)
	if err != nil {
		return nil, err
	}

	// Only admins are allowed to retrieve unvetted tokens. A user may
	// or may not exist.
	if u == nil || !u.Admin {
		ir.Unvetted = map[string][]string{}
	}

	return &v1.InventoryReply{
		Unvetted: ir.Unvetted,
		Vetted:   ir.Vetted,
	}, nil
}

func (r *Records) processTimestamps(ctx context.Context, t v1.Timestamps, isAdmin bool) (*v1.TimestampsReply, error) {
	log.Tracef("processTimestamps: %v %v", t.Token, t.Version)

	// Get record timestamps
	rt, err := r.politeiad.RecordTimestamps(ctx, t.Token, t.Version)
	if err != nil {
		return nil, err
	}

	var (
		recordMD = convertTimestampToV1(rt.RecordMetadata)
		metadata = make(map[string]map[uint32]v1.Timestamp, len(rt.Files))
		files    = make(map[string]v1.Timestamp, len(rt.Files))
	)
	for pluginID, v := range rt.Metadata {
		streams, ok := metadata[pluginID]
		if !ok {
			streams = make(map[uint32]v1.Timestamp, 16)
		}
		for streamID, ts := range v {
			streams[streamID] = convertTimestampToV1(ts)
		}
		metadata[pluginID] = streams
	}
	for k, v := range rt.Files {
		files[k] = convertTimestampToV1(v)
	}

	// Get the record. We need to know the record state.
	rc, err := r.record(ctx, t.Token, t.Version)
	if err != nil {
		return nil, err
	}

	// Unvetted data blobs are stripped if the user is not an admin.
	// The rest of the timestamp is still returned.
	if rc.State == v1.RecordStateUnvetted && !isAdmin {
		recordMD.Data = ""
		for k, v := range files {
			v.Data = ""
			files[k] = v
		}
		for _, streams := range metadata {
			for streamID, ts := range streams {
				ts.Data = ""
				streams[streamID] = ts
			}
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

	urr, err := r.politeiad.UserRecords(ctx, ur.UserID)
	if err != nil {
		return nil, err
	}

	// Determine if unvetted tokens should be returned
	switch {
	case u == nil:
		// No user session. Remove unvetted.
		urr.Unvetted = []string{}
	case u.Admin:
		// User is an admin. Return unvetted.
	case ur.UserID == u.ID.String():
		// User is requesting their own records. Return unvetted.
	default:
		// Remove unvetted for all other cases
		urr.Unvetted = []string{}
	}

	return &v1.UserRecordsReply{
		Unvetted: urr.Unvetted,
		Vetted:   urr.Vetted,
	}, nil
}

func (r *Records) records(ctx context.Context, reqs []pdv2.RecordRequest) (map[string]v1.Record, error) {
	// Get records
	pdr, err := r.politeiad.Records(ctx, reqs)
	if err != nil {
		return nil, err
	}

	// Convert records
	records := make(map[string]v1.Record, len(pdr))
	for k, v := range pdr {
		rc, err := r.convertRecordToV1(v)
		if err != nil {
			return nil, err
		}
		records[k] = *rc
	}

	return records, nil
}

var (
	errRecordNotFound = errors.New("record not found")
)

// record returns a version of a record from politeiad. If version is an empty
// string then the most recent version will be returned.
func (r *Records) record(ctx context.Context, token string, version uint32) (*v1.Record, error) {
	reqs := []pdv2.RecordRequest{
		{
			Token:   token,
			Version: version,
		},
	}
	rcs, err := r.records(ctx, reqs)
	if err != nil {
		return nil, err
	}
	rc, ok := rcs[token]
	if !ok {
		return nil, errRecordNotFound
	}
	return &rc, nil
}

func (r *Records) convertRecordToV1(pdr pdv2.Record) (*v1.Record, error) {
	rc := convertRecordToV1(pdr)

	// Fill in user data
	userID := userIDFromMetadataStreams(rc.Metadata)
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	u, err := r.userdb.UserGetById(uid)
	if err != nil {
		return nil, err
	}
	recordPopulateUserData(&rc, *u)

	return &rc, nil
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
			v.StreamID != usermd.StreamIDUserMetadata {
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

func convertStateToV1(s pdv2.RecordStateT) v1.RecordStateT {
	switch s {
	case pdv2.RecordStateUnvetted:
		return v1.RecordStateUnvetted
	case pdv2.RecordStateVetted:
		return v1.RecordStateVetted
	}
	return v1.RecordStateInvalid
}

func convertStatusToV1(s pdv2.RecordStatusT) v1.RecordStatusT {
	switch s {
	case pdv2.RecordStatusUnreviewed:
		return v1.RecordStatusUnreviewed
	case pdv2.RecordStatusPublic:
		return v1.RecordStatusPublic
	case pdv2.RecordStatusCensored:
		return v1.RecordStatusCensored
	case pdv2.RecordStatusArchived:
		return v1.RecordStatusArchived
	}
	return v1.RecordStatusInvalid
}

func convertFilesToV1(f []pdv2.File) []v1.File {
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

func convertMetadataStreamsToV1(ms []pdv2.MetadataStream) []v1.MetadataStream {
	metadata := make([]v1.MetadataStream, 0, len(ms))
	for _, v := range ms {
		metadata = append(metadata, v1.MetadataStream{
			PluginID: v.PluginID,
			StreamID: v.StreamID,
			Payload:  v.Payload,
		})
	}
	return metadata
}

func convertRecordToV1(r pdv2.Record) v1.Record {
	// User fields that are not part of the politeiad record have
	// been intentionally left blank. These fields must be pulled
	// from the user database.
	return v1.Record{
		State:     convertStateToV1(r.State),
		Status:    convertStatusToV1(r.Status),
		Version:   r.Version,
		Timestamp: r.Timestamp,
		Username:  "", // Intentionally left blank
		Metadata:  convertMetadataStreamsToV1(r.Metadata),
		Files:     convertFilesToV1(r.Files),
		CensorshipRecord: v1.CensorshipRecord{
			Token:     r.CensorshipRecord.Token,
			Merkle:    r.CensorshipRecord.Merkle,
			Signature: r.CensorshipRecord.Signature,
		},
	}
}

func convertProofToV1(p pdv2.Proof) v1.Proof {
	return v1.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestampToV1(t pdv2.Timestamp) v1.Timestamp {
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

func convertFilesToPD(f []v1.File) []pdv2.File {
	files := make([]pdv2.File, 0, len(f))
	for _, v := range f {
		files = append(files, pdv2.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}
	return files
}

func convertStateToPD(s v1.RecordStateT) pdv2.RecordStateT {
	switch s {
	case v1.RecordStateUnvetted:
		return pdv2.RecordStateUnvetted
	case v1.RecordStateVetted:
		return pdv2.RecordStateVetted
	}
	return pdv2.RecordStateInvalid
}

func convertStatusToPD(s v1.RecordStatusT) pdv2.RecordStatusT {
	switch s {
	case v1.RecordStatusUnreviewed:
		return pdv2.RecordStatusUnreviewed
	case v1.RecordStatusPublic:
		return pdv2.RecordStatusPublic
	case v1.RecordStatusCensored:
		return pdv2.RecordStatusCensored
	case v1.RecordStatusArchived:
		return pdv2.RecordStatusArchived
	}
	return pdv2.RecordStatusInvalid
}

func convertRequestsToPD(reqs []v1.RecordRequest) []pdv2.RecordRequest {
	r := make([]pdv2.RecordRequest, 0, len(reqs))
	for _, v := range reqs {
		// The records API returns the record without any files by
		// default. Files are only returned if the filenames are
		// provided. This behavior differs from the politeiad API
		// behavior, which returns all files by default.
		var omitAllFiles bool
		if len(v.Filenames) == 0 {
			omitAllFiles = true
		}
		r = append(r, pdv2.RecordRequest{
			Token:        v.Token,
			Filenames:    v.Filenames,
			OmitAllFiles: omitAllFiles,
		})
	}
	return r
}
