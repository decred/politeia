package main

import (
	"encoding/json"
	"fmt"

	backendv1 "github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backendv2"
)

// This file will contain the conversion helper functions between the backend's
// v1 types and v2 types.

// Missing data for 1-to-1 conversion:
//   - record state
func convertProposalMD(payload []byte) (*backendv2.RecordMetadata, error) {
	var mdv1 *backendv1.RecordMetadata
	err := json.Unmarshal(payload, &mdv1)
	if err != nil {
		return nil, err
	}

	var mdv2 backendv2.RecordMetadata
	mdv2.Token = mdv1.Token
	mdv2.Version = uint32(mdv1.Version)
	mdv2.Iteration = uint32(mdv1.Iteration)
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

	fmt.Println(mdv2)

	return &mdv2, nil
}
