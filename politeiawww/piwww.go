// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	wwwutil "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
)

// TODO use pi errors instead of www errors

func convertUserErrFromSignatureErr(err error) www.UserError {
	var e util.SignatureError
	var s www.ErrorStatusT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = www.ErrorStatusInvalidPublicKey
		case util.ErrorStatusSignatureInvalid:
			s = www.ErrorStatusInvalidSignature
		}
	}
	return www.UserError{
		ErrorCode:    s,
		ErrorContext: e.ErrorContext,
	}
}

func verifyProposal(files []pi.File, metadata []pi.Metadata, publicKey, signature string) error {
	if len(files) == 0 {
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalMissingFiles,
			ErrorContext: []string{"no files found"},
		}
	}

	// Verify the files adhere to all policy requirements
	var (
		countTextFiles  int
		countImageFiles int
		foundIndexFile  bool
	)
	filenames := make(map[string]struct{}, len(files))
	for _, v := range files {
		// Validate file name
		_, ok := filenames[v.Name]
		if ok {
			return www.UserError{
				ErrorCode:    www.ErrorStatusProposalDuplicateFilenames,
				ErrorContext: []string{v.Name},
			}
		}
		filenames[v.Name] = struct{}{}

		// Validate file payload
		if v.Payload == "" {
			e := fmt.Sprintf("base64 payload is empty for file '%v'",
				v.Name)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidBase64,
				ErrorContext: []string{e},
			}
		}
		payloadb, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidBase64,
				ErrorContext: []string{v.Name},
			}
		}

		// Verify computed file digest matches given file digest
		digest := util.Digest(payloadb)
		d, ok := util.ConvertDigest(v.Digest)
		if !ok {
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{v.Name},
			}
		}
		if !bytes.Equal(digest, d[:]) {
			e := fmt.Sprintf("computed digest does not match given digest "+
				"for file '%v'", v.Name)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{e},
			}
		}

		// Verify detected MIME type matches given mime type
		ct := http.DetectContentType(payloadb)
		mimePayload, _, err := mime.ParseMediaType(ct)
		if err != nil {
			return err
		}
		mimeFile, _, err := mime.ParseMediaType(v.MIME)
		if err != nil {
			log.Debugf("validateProposal: ParseMediaType(%v): %v",
				v.MIME, err)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidMIMEType,
				ErrorContext: []string{v.Name},
			}
		}
		if mimeFile != mimePayload {
			e := fmt.Sprintf("detected mime '%v' does not match '%v' for file '%v'",
				mimePayload, mimeFile, v.Name)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidMIMEType,
				ErrorContext: []string{e},
			}
		}

		// Run MIME type specific validation
		switch mimeFile {
		case mimeTypeText:
			countTextFiles++

			// Verify text file size
			if len(payloadb) > www.PolicyMaxMDSize {
				e := fmt.Sprintf("file size %v exceeds max %v for file '%v'",
					len(payloadb), www.PolicyMaxMDSize, v.Name)
				return www.UserError{
					ErrorCode:    www.ErrorStatusMaxMDSizeExceededPolicy,
					ErrorContext: []string{e},
				}
			}

			// The only text file that is allowed is the index markdown
			// file.
			if v.Name != www.PolicyIndexFilename {
				return www.UserError{
					ErrorCode:    www.ErrorStatusMaxMDsExceededPolicy,
					ErrorContext: []string{v.Name},
				}
			}
			if foundIndexFile {
				e := fmt.Sprintf("more than one %v file found",
					www.PolicyIndexFilename)
				return www.UserError{
					ErrorCode:    www.ErrorStatusMaxMDsExceededPolicy,
					ErrorContext: []string{e},
				}
			}

			// Set index file as being found
			foundIndexFile = true

		case mimeTypePNG:
			countImageFiles++

			// Verify image file size
			if len(payloadb) > www.PolicyMaxImageSize {
				e := fmt.Sprintf("file size %v exceeds max %v for file '%v'",
					len(payloadb), www.PolicyMaxImageSize, v.Name)
				return www.UserError{
					ErrorCode:    www.ErrorStatusMaxImageSizeExceededPolicy,
					ErrorContext: []string{e},
				}
			}

		default:
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidMIMEType,
				ErrorContext: []string{v.MIME},
			}
		}
	}

	// Verify that an index file is present.
	if !foundIndexFile {
		e := fmt.Sprintf("%v file not found", www.PolicyIndexFilename)
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalMissingFiles,
			ErrorContext: []string{e},
		}
	}

	// Verify file counts are acceptable
	if countTextFiles > www.PolicyMaxMDs {
		e := fmt.Sprintf("got %v text files; max is %v",
			countTextFiles, www.PolicyMaxMDs)
		return www.UserError{
			ErrorCode:    www.ErrorStatusMaxMDsExceededPolicy,
			ErrorContext: []string{e},
		}
	}
	if countImageFiles > www.PolicyMaxImages {
		e := fmt.Sprintf("got %v image files, max is %v",
			countImageFiles, www.PolicyMaxImages)
		return www.UserError{
			ErrorCode:    www.ErrorStatusMaxImagesExceededPolicy,
			ErrorContext: []string{e},
		}
	}

	// Verify signature
	mr, err := wwwutil.MerkleRoot(files, metadata)
	if err != nil {
		return fmt.Errorf("MerkleRoot: %v", err)
	}
	err = util.VerifySignature(signature, publicKey, mr)
	if err != nil {
		return convertUserErrFromSignatureErr(err)
	}

	return nil
}

func (p *politeiawww) processProposalNew(pn pi.ProposalNew, usr user.User) (*pi.ProposalNewReply, error) {
	log.Tracef("processProposalNew: %v", usr.Username)

	// Verify user has paid the registration paywall
	if !p.HasUserPaid(&usr) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	// Verify user has a proposal credit to spend
	if !p.UserHasProposalCredits(&usr) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoProposalCredits,
		}
	}

	// Verify the user signed using their active identitiy
	if usr.PublicKey() != pn.PublicKey {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Verify proposal
	err := verifyProposal(pn.Files, pn.Metadata, pn.PublicKey, pn.Signature)
	if err != nil {
		return nil, err
	}

	// Setup metadata stream

	// Send politeiad request

	// Handle response

	// Deduct proposal credit from author's account

	// Fire off a new proposal event

	return nil, nil
}
