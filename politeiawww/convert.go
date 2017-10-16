package main

import (
	pd "github.com/decred/politeia/politeiad/api/v1"
	www "github.com/decred/politeia/politeiawww/api/v1"
)

func convertPropStatusFromWWW(s www.PropStatusT) pd.StatusT {
	switch s {
	case www.PropStatusNotFound:
		return pd.StatusNotFound
	case www.PropStatusNotReviewed:
		return pd.StatusNotReviewed
	case www.PropStatusCensored:
		return pd.StatusCensored
	case www.PropStatusPublic:
		return pd.StatusPublic
	}
	return pd.StatusInvalid
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
		Name:             p.Name,
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
func convertPropStatusFromPD(s pd.StatusT) www.PropStatusT {
	switch s {
	case pd.StatusNotFound:
		return www.PropStatusNotFound
	case pd.StatusNotReviewed:
		return www.PropStatusNotReviewed
	case pd.StatusCensored:
		return www.PropStatusCensored
	case pd.StatusPublic:
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
		Name:             p.Name,
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
