package main

import (
	pd "github.com/decred/politeia/politeiad/api/v1"
	www "github.com/decred/politeia/politeiawww/api/v1"
)

func convertPropStatusFromWWW(s www.PropStatusT) pd.PropStatusT {
	switch s {
	case www.PropStatusNotFound:
		return pd.PropStatusNotFound
	case www.PropStatusNotReviewed:
		return pd.PropStatusNotReviewed
	case www.PropStatusCensored:
		return pd.PropStatusCensored
	case www.PropStatusPublic:
		return pd.PropStatusPublic
	}
	return pd.PropStatusInvalid
}

func convertPropFileFromWWW(f www.File) pd.File {
	return pd.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertPropFilesFromWWW(f []www.File) []pd.File {
	files := make([]pd.File, 0, len(f))
	for _, v := range f {
		files = append(files, convertPropFileFromWWW(v))
	}
	return files
}

func convertPropCensorFromWWW(f www.CensorshipRecord) pd.CensorshipRecord {
	return pd.CensorshipRecord{
		Token:     f.Token,
		Merkle:    f.Merkle,
		Signature: f.Signature,
	}
}

func convertPropFromWWW(p www.ProposalRecord) pd.ProposalRecord {
	return pd.ProposalRecord{
		Status:           convertPropStatusFromWWW(p.Status),
		Timestamp:        p.Timestamp,
		Files:            convertPropFilesFromWWW(p.Files),
		CensorshipRecord: convertPropCensorFromWWW(p.CensorshipRecord),
	}
}

func convertPropsFromWWW(p []www.ProposalRecord) []pd.ProposalRecord {
	pr := make([]pd.ProposalRecord, 0, len(p))
	for _, v := range p {
		pr = append(pr, convertPropFromWWW(v))
	}
	return pr
}

///////////////////////////////
func convertPropStatusFromPD(s pd.PropStatusT) www.PropStatusT {
	switch s {
	case pd.PropStatusNotFound:
		return www.PropStatusNotFound
	case pd.PropStatusNotReviewed:
		return www.PropStatusNotReviewed
	case pd.PropStatusCensored:
		return www.PropStatusCensored
	case pd.PropStatusPublic:
		return www.PropStatusPublic
	}
	return www.PropStatusInvalid
}

func convertPropFileFromPD(f pd.File) www.File {
	return www.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertPropFilesFromPD(f []pd.File) []www.File {
	files := make([]www.File, 0, len(f))
	for _, v := range f {
		files = append(files, convertPropFileFromPD(v))
	}
	return files
}

func convertPropCensorFromPD(f pd.CensorshipRecord) www.CensorshipRecord {
	return www.CensorshipRecord{
		Token:     f.Token,
		Merkle:    f.Merkle,
		Signature: f.Signature,
	}
}

func convertPropFromPD(p pd.ProposalRecord) www.ProposalRecord {
	return www.ProposalRecord{
		Status:           convertPropStatusFromPD(p.Status),
		Timestamp:        p.Timestamp,
		Files:            convertPropFilesFromPD(p.Files),
		CensorshipRecord: convertPropCensorFromPD(p.CensorshipRecord),
	}
}

func convertPropsFromPD(p []pd.ProposalRecord) []www.ProposalRecord {
	pr := make([]www.ProposalRecord, 0, len(p))
	for _, v := range p {
		pr = append(pr, convertPropFromPD(v))
	}
	return pr
}

func convertErrorStatusFromPD(s int) www.ErrorStatusT {
	switch pd.ErrorStatusT(s) {
	case pd.ErrorStatusInvalidProposalName:
		return www.ErrorStatusInvalidProposalName
	case pd.ErrorStatusInvalidFileDigest:
		return www.ErrorStatusInvalidFileDigest
	case pd.ErrorStatusInvalidBase64:
		return www.ErrorStatusInvalidBase64
	case pd.ErrorStatusInvalidMIMEType:
		return www.ErrorStatusInvalidMIMEType
	case pd.ErrorStatusUnsupportedMIMEType:
		return www.ErrorStatusUnsupportedMIMEType
	case pd.ErrorStatusInvalidPropStatusTransition:
		return www.ErrorStatusInvalidPropStatusTransition

		// These cases are intentionally omitted because
		// they are indicative of some internal server error,
		// so ErrorStatusInvalid is returned.
		//
		//case pd.ErrorStatusInvalidRequestPayload
		//case pd.ErrorStatusInvalidChallenge
	}
	return www.ErrorStatusInvalid
}
