// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

/*
var (
	// errProposalNotFound is emitted when a proposal is not found in
	// politeiad for a specified token and version.
	errProposalNotFound = errors.New("proposal not found")
)

// proposalName parses the proposal name from the ProposalMetadata and returns
// it. An empty string will be returned if any errors occur or if a name is not
// found.
func proposalName(r pdv1.Record) string {
	var name string
	for _, v := range r.Files {
		if v.Name == pi.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return ""
			}
			var pm pi.ProposalMetadata
			err = json.Unmarshal(b, &pm)
			if err != nil {
				return ""
			}
			name = pm.Name
		}
	}
	return name
}

// proposalRecordFillInUser fills in all user fields that are store in the
// user database and not in politeiad.
func proposalRecordFillInUser(pr piv1.ProposalRecord, u user.User) piv1.ProposalRecord {
	pr.UserID = u.ID.String()
	pr.Username = u.Username
	return pr
}

func convertRecordStatusFromPropStatus(s piv1.PropStatusT) pdv1.RecordStatusT {
	switch s {
	case piv1.PropStatusUnreviewed:
		return pdv1.RecordStatusNotReviewed
	case piv1.PropStatusPublic:
		return pdv1.RecordStatusPublic
	case piv1.PropStatusCensored:
		return pdv1.RecordStatusCensored
	case piv1.PropStatusAbandoned:
		return pdv1.RecordStatusArchived
	}
	return pdv1.RecordStatusInvalid
}

func convertFileFromMetadata(m piv1.Metadata) pdv1.File {
	var name string
	switch m.Hint {
	case piv1.HintProposalMetadata:
		name = pi.FileNameProposalMetadata
	}
	return pdv1.File{
		Name:    name,
		MIME:    mimeTypeTextUTF8,
		Digest:  m.Digest,
		Payload: m.Payload,
	}
}

func convertFileFromPi(f piv1.File) pdv1.File {
	return pdv1.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertFilesFromPi(files []piv1.File) []pdv1.File {
	f := make([]pdv1.File, 0, len(files))
	for _, v := range files {
		f = append(f, convertFileFromPi(v))
	}
	return f
}

func convertPropStatusFromPD(s pdv1.RecordStatusT) piv1.PropStatusT {
	switch s {
	case pdv1.RecordStatusNotFound:
		// Intentionally omitted. No corresponding PropStatusT.
	case pdv1.RecordStatusNotReviewed:
		return piv1.PropStatusUnreviewed
	case pdv1.RecordStatusCensored:
		return piv1.PropStatusCensored
	case pdv1.RecordStatusPublic:
		return piv1.PropStatusPublic
	case pdv1.RecordStatusUnreviewedChanges:
		return piv1.PropStatusUnreviewed
	case pdv1.RecordStatusArchived:
		return piv1.PropStatusAbandoned
	}
	return piv1.PropStatusInvalid
}

func convertCensorshipRecordFromPD(cr pdv1.CensorshipRecord) piv1.CensorshipRecord {
	return piv1.CensorshipRecord{
		Token:     cr.Token,
		Merkle:    cr.Merkle,
		Signature: cr.Signature,
	}
}

func convertFilesFromPD(f []pdv1.File) ([]piv1.File, []piv1.Metadata) {
	files := make([]piv1.File, 0, len(f))
	metadata := make([]piv1.Metadata, 0, len(f))
	for _, v := range f {
		switch v.Name {
		case pi.FileNameProposalMetadata:
			metadata = append(metadata, piv1.Metadata{
				Hint:    piv1.HintProposalMetadata,
				Digest:  v.Digest,
				Payload: v.Payload,
			})
		default:
			files = append(files, piv1.File{
				Name:    v.Name,
				MIME:    v.MIME,
				Digest:  v.Digest,
				Payload: v.Payload,
			})
		}
	}
	return files, metadata
}

func statusChangesDecode(payload []byte) ([]rcv1.StatusChange, error) {
	var statuses []rcv1.StatusChange
	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var sc rcv1.StatusChange
		err := d.Decode(&sc)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		statuses = append(statuses, sc)
	}
	return statuses, nil
}

func convertProposalRecordFromPD(r pdv1.Record, state piv1.PropStateT) (*piv1.ProposalRecord, error) {
	// Decode metadata streams
	var (
		um  *usermd.UserMetadata
		sc  = make([]pi.StatusChange, 0, 16)
		err error
	)
	for _, v := range r.Metadata {
		switch v.ID {
		case usermd.MDStreamIDUserMetadata:
			var um usermd.UserMetadata
			err = json.Unmarshal([]byte(v.Payload), &um)
			if err != nil {
				return nil, err
			}
		case pi.MDStreamIDStatusChanges:
			sc, err = statusChangesDecode([]byte(v.Payload))
			if err != nil {
				return nil, err
			}
		}
	}

	// Convert to pi types
	files, metadata := convertFilesFromPD(r.Files)
	status := convertPropStatusFromPD(r.Status)

	statuses := make([]piv1.StatusChange, 0, len(sc))
	for _, v := range sc {
		statuses = append(statuses, piv1.StatusChange{
			Token:     v.Token,
			Version:   v.Version,
			Status:    piv1.PropStatusT(v.Status),
			Reason:    v.Reason,
			PublicKey: v.PublicKey,
			Signature: v.Signature,
			Timestamp: v.Timestamp,
		})
	}

	// Some fields are intentionally omitted because they are either
	// user data that needs to be pulled from the user database or they
	// are politeiad plugin data that needs to be retrieved using a
	// plugin command.
	return &piv1.ProposalRecord{
		Version:          r.Version,
		Timestamp:        r.Timestamp,
		State:            state,
		Status:           status,
		UserID:           um.UserID,
		Username:         "", // Intentionally omitted
		PublicKey:        um.PublicKey,
		Signature:        um.Signature,
		Statuses:         statuses,
		Files:            files,
		Metadata:         metadata,
		CensorshipRecord: convertCensorshipRecordFromPD(r.CensorshipRecord),
	}, nil
}

// proposalRecords returns the ProposalRecord for each of the provided proposal
// requests. If a token does not correspond to an actual proposal then it will
// not be included in the returned map.
func (p *politeiawww) proposalRecords(ctx context.Context, state piv1.PropStateT, reqs []piv1.ProposalRequest, includeFiles bool) (map[string]piv1.ProposalRecord, error) {
	// Get politeiad records
	props := make([]piv1.ProposalRecord, 0, len(reqs))
	for _, v := range reqs {
		var r *pdv1.Record
		var err error
		switch state {
		case piv1.PropStateUnvetted:
			// Unvetted politeiad record
			r, err = p.politeiad.GetUnvetted(ctx, v.Token, v.Version)
			if err != nil {
				return nil, err
			}
		case piv1.PropStateVetted:
			// Vetted politeiad record
			r, err = p.politeiad.GetVetted(ctx, v.Token, v.Version)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown state %v", state)
		}

		if r.Status == pdv1.RecordStatusNotFound {
			// Record wasn't found. Don't include token in the results.
			continue
		}

		pr, err := convertProposalRecordFromPD(*r, state)
		if err != nil {
			return nil, err
		}

		// Remove files if specified. The Metadata objects will still be
		// returned.
		if !includeFiles {
			pr.Files = []piv1.File{}
		}

		props = append(props, *pr)
	}

	// Verify we've got some results
	if len(props) == 0 {
		return map[string]piv1.ProposalRecord{}, nil
	}

	// Get user data
	pubkeys := make([]string, 0, len(props))
	for _, v := range props {
		pubkeys = append(pubkeys, v.PublicKey)
	}
	ur, err := p.db.UsersGetByPubKey(pubkeys)
	if err != nil {
		return nil, err
	}
	for k, v := range props {
		token := v.CensorshipRecord.Token
		u, ok := ur[v.PublicKey]
		if !ok {
			return nil, fmt.Errorf("user not found for pubkey %v from proposal %v",
				v.PublicKey, token)
		}
		props[k] = proposalRecordFillInUser(v, u)
	}

	// Convert proposals to a map
	proposals := make(map[string]piv1.ProposalRecord, len(props))
	for _, v := range props {
		proposals[v.CensorshipRecord.Token] = v
	}

	return proposals, nil
}

// proposalRecord returns the proposal record for the provided token and
// version. A blank version will return the most recent version. A
// errProposalNotFound error will be returned if a proposal is not found for
// the provided token/version combination.
func (p *politeiawww) proposalRecord(ctx context.Context, state piv1.PropStateT, token, version string) (*piv1.ProposalRecord, error) {
	prs, err := p.proposalRecords(ctx, state, []piv1.ProposalRequest{
		{
			Token:   token,
			Version: version,
		},
	}, true)
	if err != nil {
		return nil, err
	}
	pr, ok := prs[token]
	if !ok {
		return nil, errProposalNotFound
	}
	return &pr, nil
}

// proposalRecordLatest returns the latest version of the proposal record for
// the provided token. A errProposalNotFound error will be returned if a
// proposal is not found for the provided token.
func (p *politeiawww) proposalRecordLatest(ctx context.Context, state piv1.PropStateT, token string) (*piv1.ProposalRecord, error) {
	return p.proposalRecord(ctx, state, token, "")
}
*/
