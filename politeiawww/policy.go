package main

import (
	"github.com/decred/politeia/politeiad/api/v1/mime"
	www "github.com/decred/politeia/politeiawww/api/v1"
)

// ProcessPolicy returns the details of Politeia's restrictions on file uploads.
func (b *backend) ProcessPolicy(p www.Policy) *www.PolicyReply {
	return &www.PolicyReply{
		PasswordMinChars:     www.PolicyPasswordMinChars,
		ProposalListPageSize: www.ProposalListPageSize,
		MaxImages:            www.PolicyMaxImages,
		MaxImageSize:         www.PolicyMaxImageSize,
		MaxMDs:               www.PolicyMaxMDs,
		MaxMDSize:            www.PolicyMaxMDSize,
		ValidMIMETypes:       mime.ValidMimeTypes(),
		MaxNameLength:        www.PolicyMaxProposalNameLength,
		MinNameLength:        www.PolicyMinProposalNameLength,
		SupportedCharacters:  www.PolicyProposalNameSupportedCharacters,
		MaxCommentLength:     www.PolicyMaxCommentLength,
	}
}
