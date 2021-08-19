package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/decred/politeia/mdstream"
	backendv1 "github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backendv2"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	pusermd "github.com/decred/politeia/politeiad/plugins/usermd"
)

// convertRecordMetadata reads the recordmetadata.json from the gitbe record
// and converts it to a v2 RecordMetadata for the tlogbe.
func convertRecordMetadata(path string) (*backendv2.RecordMetadata, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var mdv1 *backendv1.RecordMetadata
	err = json.Unmarshal(b, &mdv1)
	if err != nil {
		return nil, err
	}

	var mdv2 backendv2.RecordMetadata
	mdv2.Version = 1
	mdv2.Token = mdv1.Token
	mdv2.Iteration = 1
	mdv2.State = backend.StateVetted
	mdv2.Timestamp = mdv1.Timestamp
	mdv2.Merkle = mdv1.Merkle

	// Convert status
	// TODO: right?
	switch {
	case mdv1.Status == backendv1.MDStatusInvalid:
		mdv2.Status = backendv2.StatusInvalid
	case mdv1.Status == backendv1.MDStatusUnvetted:
		mdv2.Status = backendv2.StatusUnreviewed
	case mdv1.Status == backendv1.MDStatusVetted:
		mdv2.Status = backendv2.StatusPublic
	case mdv1.Status == backendv1.MDStatusCensored:
		mdv2.Status = backendv2.StatusCensored
	case mdv1.Status == backendv1.MDStatusIterationUnvetted:
		mdv2.Status = backendv2.StatusUnreviewed
	case mdv1.Status == backendv1.MDStatusArchived:
		mdv2.Status = backendv2.StatusArchived
	default:
		return nil, err
	}

	return &mdv2, nil
}

// convertStatusChangeMetadata converts the 02.metadata.txt status change md
// from legacy git records.
func convertStatusChangeMetadata(path string) (*usermd.StatusChangeMetadata, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rsc mdstream.RecordStatusChangeV2
	err = json.Unmarshal(b, &rsc)
	if err != nil {
		return nil, err
	}

	return &pusermd.StatusChangeMetadata{
		Version:   uint32(rsc.Version),
		Status:    uint32(rsc.NewStatus),
		Reason:    rsc.StatusChangeMessage,
		PublicKey: rsc.AdminPubKey,
		Signature: rsc.Signature,
		Timestamp: rsc.Timestamp,
	}, nil
}

// convertProposalGeneral converts the ProposalGeneralV1 metadata structure
// previously used on legacy git records.
func (l *legacyImport) convertProposalGeneral(path string) (*usermd.UserMetadata, string, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	// If name is unmarshalled to null, then proposal general is version 2.
	var pgv1 proposalGeneralV1
	err = json.Unmarshal(b, &pgv1)
	if err != nil {
		return nil, "", err
	}

	_, err = l.fetchUserByPubKey(pgv1.PublicKey)
	if err != nil {
		return nil, "", err
	}

	// If userid/publickey are data from a user that is not registered in the
	// userdb this tool is using, then recordSave will error out.
	return &pusermd.UserMetadata{
		// UserID:    usr.ID,
		// PublicKey: pgv1.PublicKey,

		// test with user data that exists in local user db
		UserID:    "7a74252c-400f-430d-9eb3-50525104736b",
		PublicKey: "7ef4bae79cd0e28375b28fc8c7c6c0e825d1dd1b1105392f685230f22cc420e5",
		Signature: pgv1.Signature,
	}, pgv1.Name, nil
}
