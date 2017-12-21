package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
	"github.com/stretchr/testify/suite"
)

// ProposalsTestSuite tests the logic concerning proposals. Inherits the backend setup
// and teardown, as well as all the testify suite methods from BackendTestSuite
type ProposalsTestSuite struct {
	BackendTestSuite
}

func TestProposalTestSuite(t *testing.T) {
	suite.Run(t, new(ProposalsTestSuite))
}

// ProposalRequest represents the input object for the proposal creation method
type ProposalRequest struct {
	NumMDs          uint
	NumImages       uint
	MDSize          uint
	MDTitleLength   uint
	ImageSize       uint
	DuplicatedFiles bool
	NoIndexFile     bool
	InvalidTitle    bool
}

// NewDefaultProposalRequest
func NewDefaultProposalRequest() *ProposalRequest {
	return &ProposalRequest{
		NumMDs: 1,
	}
}

func (s *ProposalsTestSuite) TestCreateProposal() {
	policy := s.backend.ProcessPolicy(www.Policy{})

	testCases := []struct {
		name          string
		input         *ProposalRequest
		expectedError error
	}{
		{
			name: "success - max allowed",
			input: &ProposalRequest{
				NumMDs:        policy.MaxMDs,
				NumImages:     policy.MaxImages,
				MDSize:        policy.MaxMDSize,
				ImageSize:     policy.MaxImageSize,
				MDTitleLength: www.PolicyMinProposalNameLength + 1,
			},
			expectedError: nil,
		},
		{
			name: "failure - number of MDs excedeed",
			input: &ProposalRequest{
				NumMDs: policy.MaxMDs + 1,
			},
			expectedError: www.UserError{
				ErrorCode: www.ErrorStatusMaxMDsExceededPolicy,
			},
		},
		{
			name: "failure - number of images excedeed",
			input: &ProposalRequest{
				NumMDs:    1,
				NumImages: policy.MaxImages + 1,
			},
			expectedError: www.UserError{
				ErrorCode: www.ErrorStatusMaxImagesExceededPolicy,
			},
		},
		{
			name:  "failure - no files",
			input: &ProposalRequest{},
			expectedError: www.UserError{
				ErrorCode: www.ErrorStatusProposalMissingFiles,
			},
		},
		{
			name: "failure - max md size excedeed",
			input: &ProposalRequest{
				NumMDs: 1,
				MDSize: policy.MaxMDSize + 1,
			},
			expectedError: www.UserError{
				ErrorCode: www.ErrorStatusMaxMDSizeExceededPolicy,
			},
		},
		{
			name: "failure - max image size excedeed",
			input: &ProposalRequest{
				NumMDs:    1,
				NumImages: 1,
				ImageSize: policy.MaxImageSize + 1,
			},
			expectedError: www.UserError{
				ErrorCode: www.ErrorStatusMaxImageSizeExceededPolicy,
			},
		},
		{
			name: "failure - invalid title characters",
			input: &ProposalRequest{
				NumMDs:       1,
				InvalidTitle: true,
			},
			expectedError: www.UserError{
				ErrorCode:    www.ErrorStatusProposalInvalidTitle,
				ErrorContext: []string{util.CreateProposalTitleRegex()},
			},
		},
		{
			name: "failure - duplicate files",
			input: &ProposalRequest{
				NumMDs:          2,
				DuplicatedFiles: true,
			},
			expectedError: www.UserError{
				ErrorCode:    www.ErrorStatusProposalDuplicateFilenames,
				ErrorContext: []string{indexFile},
			},
		},
		{
			name: "failure - create proposal without index file",
			input: &ProposalRequest{
				NumMDs:      1,
				NoIndexFile: true,
			},
			expectedError: www.UserError{
				ErrorCode:    www.ErrorStatusProposalMissingFiles,
				ErrorContext: []string{indexFile},
			},
		},
		{
			name: "failure - proposal title size excedeed",
			input: &ProposalRequest{
				NumMDs:        1,
				MDTitleLength: www.PolicyMaxProposalNameLength + 1,
			},
			expectedError: www.UserError{
				ErrorCode:    www.ErrorStatusProposalInvalidTitle,
				ErrorContext: []string{util.CreateProposalTitleRegex()},
			},
		},
		{
			name: "failure - proposal title minimum size policy not met",
			input: &ProposalRequest{
				NumMDs:        1,
				MDTitleLength: www.PolicyMinProposalNameLength - 1,
			},
			expectedError: www.UserError{
				ErrorCode:    www.ErrorStatusProposalInvalidTitle,
				ErrorContext: []string{util.CreateProposalTitleRegex()},
			},
		},
	}

	// tests
	for _, tc := range testCases {
		s.T().Run(tc.name, func(*testing.T) {
			_, reply, err := createProposal(s.backend, tc.input)
			s.EqualValues(tc.expectedError, err)
			if err == nil {
				s.NotNil(reply)
				// @TODO(rgeraldes)
				//s.NotEmpty(reply.CensorshipRecord.Token)
				//s.NotEmpty(reply.CensorshipRecord.Merkle)
				//s.NotEmpty(reply.CensorshipRecord.Signature)
			}
		})
	}
}

// Tests fetching an unreviewed proposal's details.
func (s *ProposalsTestSuite) TestUnreviewedProposal() {
	np, npr, err := createProposal(s.backend, NewDefaultProposalRequest())
	s.NoError(err)
	s.NotNil(np)
	s.NotNil(npr)

	pdr, err := getProposalDetails(s.backend, npr.CensorshipRecord.Token)
	s.NoError(err)
	s.NotNil(pdr)

	s.verifyProposalDetails(np, pdr.Proposal)
}

// Tests censoring a proposal and then fetching its details.
func (s *ProposalsTestSuite) TestCensoredProposal() {
	np, npr, err := createProposal(s.backend, NewDefaultProposalRequest())
	s.NoError(err)
	s.NotNil(np)
	s.NotNil(npr)

	s.NoError(censorProposal(s.backend, npr.CensorshipRecord.Token))

	pdr, err := getProposalDetails(s.backend, npr.CensorshipRecord.Token)
	s.NoError(err)
	s.NotNil(pdr)

	s.verifyProposalDetails(np, pdr.Proposal)
}

// Tests publishing a proposal and then fetching its details.
func (s *ProposalsTestSuite) TestPublishedProposal() {
	np, npr, err := createProposal(s.backend, NewDefaultProposalRequest())
	s.NoError(err)
	s.NotNil(np)
	s.NotNil(npr)

	s.NoError(publishProposal(s.backend, npr.CensorshipRecord.Token))

	pdr, err := getProposalDetails(s.backend, npr.CensorshipRecord.Token)
	s.NoError(err)
	s.NotNil(pdr)

	s.verifyProposalDetails(np, pdr.Proposal)
}

// Tests that the inventory is always sorted by timestamp.
func (s *ProposalsTestSuite) TestInventorySorted() {
	// Create an array of proposals, some vetted and some unvetted.
	allProposals := make([]www.ProposalRecord, 0, 5)
	vettedProposals := make([]www.ProposalRecord, 0)
	unvettedProposals := make([]www.ProposalRecord, 0)
	for i := 0; i < cap(allProposals); i++ {
		_, npr, err := createProposal(s.backend, NewDefaultProposalRequest())
		s.NoError(err)
		s.NotNil(npr)

		if i%2 == 0 {
			s.NoError(publishProposal(s.backend, npr.CensorshipRecord.Token))
		}

		pdr, err := getProposalDetails(s.backend, npr.CensorshipRecord.Token)
		s.NoError(err)
		s.NotNil(pdr)

		allProposals = append(allProposals, pdr.Proposal)
		if i%2 == 0 {
			vettedProposals = append(vettedProposals, pdr.Proposal)
		} else {
			unvettedProposals = append(unvettedProposals, pdr.Proposal)
		}

		time.Sleep(time.Duration(2) * time.Second)
	}

	/*
		fmt.Printf("Proposals:\n")
		for _, v := range proposals {
			fmt.Printf("%v %v %v\n", v.Name, v.Status, v.Timestamp)
		}
	*/

	// Verify that the proposals are returned sorted correctly.
	s.verifyProposalsSorted(vettedProposals, unvettedProposals)

	// Wipe the inventory and fetch it again.
	s.NoError(s.backend.LoadInventory())

	/*
		fmt.Printf("\nInventory:\n")
		for _, v := range b.inventory {
			fmt.Printf("%v %v %v\n", v.Name, v.Status, v.Timestamp)
		}
	*/

	// Verify that the proposals are still sorted correctly.
	s.verifyProposalsSorted(vettedProposals, unvettedProposals)
}

func (s *ProposalsTestSuite) TestProposalNumComments() {
	var (
		title    = generateRandomString(www.PolicyMinProposalNameLength)
		desc     = generateRandomString(8)
		contents = []byte(title + "\n" + desc)
	)

	files := make([]pd.File, 0, 1)
	files = append(files, pd.File{
		Name:    indexFile,
		MIME:    "text/plain; charset=utf-8",
		Payload: base64.StdEncoding.EncodeToString(contents),
	})

	signature, user, err := getProposalSignatureAndSigningUser(files)
	s.NoError(err)
	s.NotNil(user)
	s.NotEmpty(signature)

	// new proposal
	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(user.Identities[0].Key[:]),
		Signature: signature,
	}
	npr, err := s.backend.ProcessNewProposal(np, user)
	s.NoError(err)
	s.NotNil(npr)

	// publish proposal
	s.NoError(publishProposal(s.backend, npr.CensorshipRecord.Token))

	// add a comment
	_, err = s.backend.addComment(www.NewComment{
		Token:    npr.CensorshipRecord.Token,
		ParentID: "1",
		Comment:  "comment",
	}, user.ID)
	s.NoError(err)

	// process all vetted proposals
	reply := s.backend.ProcessAllVetted(www.GetAllVetted{})
	s.NotNil(reply)

	// must have one proposal
	s.Equal(1, len(reply.Proposals))

	// proposal must have one comment
	proposal := reply.Proposals[0]
	s.NotNil(*proposal.NumComments)
	s.EqualValues(1, *proposal.NumComments)
}

func (s *ProposalsTestSuite) TestProposalNumCommentsZero() {
	var (
		title    = generateRandomString(www.PolicyMinProposalNameLength)
		desc     = generateRandomString(8)
		contents = []byte(title + "\n" + desc)
	)

	files := make([]pd.File, 0, 1)
	files = append(files, pd.File{
		Name:    indexFile,
		MIME:    "text/plain; charset=utf-8",
		Payload: base64.StdEncoding.EncodeToString(contents),
	})

	signature, user, err := getProposalSignatureAndSigningUser(files)
	s.NoError(err)
	s.NotNil(user)
	s.NotEmpty(signature)

	// new proposal
	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(user.Identities[0].Key[:]),
		Signature: signature,
	}
	npr, err := s.backend.ProcessNewProposal(np, user)
	s.NoError(err)
	s.NotNil(npr)

	// publish proposal
	s.NoError(publishProposal(s.backend, npr.CensorshipRecord.Token))

	// process all vetted proposals
	reply := s.backend.ProcessAllVetted(www.GetAllVetted{})
	s.NotNil(reply)

	// must have one proposal
	s.Equal(1, len(reply.Proposals))

	// proposal must have 0 comments
	proposal := reply.Proposals[0]
	s.NotNil(*proposal.NumComments)
	s.EqualValues(0, *proposal.NumComments)
}

func (s *ProposalsTestSuite) TestProposalListPaging() {
	tokens := make([]string, www.ProposalListPageSize+1)

	for i := 0; i < www.ProposalListPageSize+1; i++ {
		_, npr, err := createProposal(s.backend, NewDefaultProposalRequest())
		s.NoError(err)
		s.NotNil(npr)

		tokens[i] = npr.CensorshipRecord.Token
	}

	var u www.GetAllUnvetted
	ur := s.backend.ProcessAllUnvetted(u)
	s.NotNil(ur)
	s.Equal(len(ur.Proposals), www.ProposalListPageSize)

	// Test fetching the next page using the After field.
	u.After = ur.Proposals[len(ur.Proposals)-1].CensorshipRecord.Token
	ur = s.backend.ProcessAllUnvetted(u)
	s.NotNil(ur)
	s.Equal(1, len(ur.Proposals))

	for _, v := range ur.Proposals {
		s.NotEqual(v.CensorshipRecord.Token, u.After)
	}

	// Test fetching the previous page using the Before field.
	u.After = ""
	u.Before = ur.Proposals[0].CensorshipRecord.Token
	ur = s.backend.ProcessAllUnvetted(u)
	s.NotNil(ur)
	s.Equal(len(ur.Proposals), www.ProposalListPageSize)

	for _, v := range ur.Proposals {
		s.NotEqual(v.CensorshipRecord.Token, u.Before)
	}

	// Publish all the proposals.
	for _, token := range tokens {
		s.NoError(publishProposal(s.backend, token))
	}

	var v www.GetAllVetted
	vr := s.backend.ProcessAllVetted(v)
	s.NotNil(vr)
	s.Equal(len(vr.Proposals), www.ProposalListPageSize)

	// Test fetching the next page using the After field.
	v.After = vr.Proposals[len(vr.Proposals)-1].CensorshipRecord.Token
	vr = s.backend.ProcessAllVetted(v)
	s.NotNil(vr)
	s.Equal(1, len(vr.Proposals))

	// Test fetching the previous page using the Before field.
	v.After = ""
	v.Before = vr.Proposals[0].CensorshipRecord.Token
	vr = s.backend.ProcessAllVetted(v)
	s.NotNil(vr)
	s.Equal(len(vr.Proposals), www.ProposalListPageSize)

}

// Tests creates a new proposal with an invalid signature.
func (s *ProposalsTestSuite) TestNewProposalWithInvalidSignature() {
	var (
		title     = generateRandomString(www.PolicyMinProposalNameLength)
		desc      = generateRandomString(8)
		signature = generateRandomString(identity.SignatureSize)
		contents  = []byte(title + "\n" + desc)
	)

	files := make([]pd.File, 0, 1)
	files = append(files, pd.File{
		Name:    indexFile,
		MIME:    "text/plain; charset=utf-8",
		Payload: base64.StdEncoding.EncodeToString(contents),
	})

	_, user, err := getProposalSignatureAndSigningUser(files)
	s.NoError(err)
	s.NotNil(user)

	// new proposal
	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(user.Identities[0].Key[:]),
		Signature: signature,
	}
	_, err = s.backend.ProcessNewProposal(np, user)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusInvalidSignature,
	}, err)
}

// Tests creates a new proposal with an invalid signature.
func (s *ProposalsTestSuite) TestNewProposalWithInvalidSigningKey() {
	var (
		title    = generateRandomString(www.PolicyMinProposalNameLength)
		desc     = generateRandomString(8)
		contents = []byte(title + "\n" + desc)
	)

	files := make([]pd.File, 0, 1)
	files = append(files, pd.File{
		Name:    indexFile,
		MIME:    "text/plain; charset=utf-8",
		Payload: base64.StdEncoding.EncodeToString(contents),
	})

	// Call getProposalSignatureAndSigningUser twice, first to get
	// the signed proposal data and second to create a user with a different
	// public key than was used to sign the proposal data.
	signature, user, err := getProposalSignatureAndSigningUser(files)
	s.NoError(err)
	s.NotNil(user)
	s.NotEmpty(signature)

	alternateID, err := generateIdentity()
	s.NoError(err)
	s.NotNil(alternateID)

	// new proposal
	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(alternateID.Public.Key[:]),
		Signature: signature,
	}
	_, err = s.backend.ProcessNewProposal(np, user)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusInvalidSigningKey,
	}, err)
}

func createProposal(backend *backend, req *ProposalRequest) (*www.NewProposal, *www.NewProposalReply, error) {
	// set defaults
	if req.MDSize == 0 {
		req.MDSize = www.PolicyMaxMDSize
	}
	if req.ImageSize == 0 {
		req.ImageSize = www.PolicyMaxImageSize
	}
	if req.MDTitleLength == 0 {
		req.MDTitleLength = www.PolicyMinProposalNameLength
	}

	files := make([]pd.File, 0, req.NumMDs+req.NumImages)

	// add md files
	for i := uint(0); i < req.NumMDs; i++ {
		// @rgeraldes - add at least one index file
		if !req.NoIndexFile && i == 0 {
			var payload string

			// decide payload
			if req.InvalidTitle {
				payload = base64.StdEncoding.EncodeToString([]byte("$%&/)Title<<>>"))
			} else {
				title := generateRandomString(int(req.MDTitleLength)) + "\n"
				body := generateRandomString(int(req.MDSize) - len(title))
				payload = base64.StdEncoding.EncodeToString([]byte(title + body))
			}

			// add index file
			files = append(files, pd.File{
				Name:    indexFile,
				MIME:    "text/plain; charset=utf-8",
				Payload: payload,
			})
		} else {
			files = append(files, pd.File{
				Name:    generateRandomString(6) + ".md",
				MIME:    "text/plain; charset=utf-8",
				Payload: base64.StdEncoding.EncodeToString([]byte(generateRandomString(int(req.MDSize)))),
			})
		}
	}

	// add image files
	for i := uint(0); i < req.NumImages; i++ {
		files = append(files, pd.File{
			Name:    generateRandomString(6) + ".png",
			MIME:    "image/png",
			Payload: base64.StdEncoding.EncodeToString([]byte(generateRandomString(int(req.ImageSize)))),
		})
	}

	// copy file names if requested
	if req.DuplicatedFiles {
		if len(files) <= 1 {
			return nil, nil, errors.New("duplicated files: number of files must be bigger than one")
		}
		files[1].Name = files[0].Name
	}

	signature, user, err := getProposalSignatureAndSigningUser(files)
	if err != nil {
		return nil, nil, err
	}

	// create new request object
	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(user.Identities[0].Key[:]),
		Signature: signature,
	}

	// backend request
	npr, err := backend.ProcessNewProposal(np, user)
	return &np, npr, err
}

func publishProposal(backend *backend, token string) error {
	sps := www.SetProposalStatus{
		Token:          token,
		ProposalStatus: www.PropStatusPublic,
	}

	msg := sps.Token + strconv.FormatUint(uint64(sps.ProposalStatus), 10)
	signature, user, err := getSignatureAndSigningUser([]byte(msg))
	if err != nil {
		return err
	}

	sps.Signature = signature

	_, err = backend.ProcessSetProposalStatus(sps, user)
	return err
}

func censorProposal(backend *backend, token string) error {
	sps := www.SetProposalStatus{
		Token:          token,
		ProposalStatus: www.PropStatusCensored,
	}

	msg := sps.Token + strconv.FormatUint(uint64(sps.ProposalStatus), 10)
	signature, user, err := getSignatureAndSigningUser([]byte(msg))
	if err != nil {
		return err
	}

	sps.Signature = signature

	_, err = backend.ProcessSetProposalStatus(sps, user)
	return err
}

func getProposalDetails(backend *backend, token string) (*www.ProposalDetailsReply, error) {
	pd := www.ProposalsDetails{
		Token: token,
	}
	pdr, err := backend.ProcessProposalDetails(pd, true)
	if err != nil {
		return nil, err
	}

	return pdr, nil
}

// getSignatureAndSigningUser generates a full identity and signs the
// provided msg with it, and then creates a user whose active public key
// is set to the generated identity's public key. This allows the tests to
// pass the signature validation in www.
func getSignatureAndSigningUser(msg []byte) (string, *database.User, error) {
	id, err := generateIdentity()
	if err != nil {
		return "", nil, err
	}

	sig := id.SignMessage(msg)

	identities := make([]database.Identity, 0, 1)
	identities = append(identities, database.Identity{
		Key:         id.Public.Key,
		Activated:   1,
		Deactivated: 0,
	})
	user := &database.User{
		Identities: identities,
	}

	return hex.EncodeToString(sig[:]), user, nil
}

// getProposalSignatureAndSigningUser takes as input a list of files and
// generates the merkle root with the file digests, then delegates to
// getSignatureAndSigningUser.
func getProposalSignatureAndSigningUser(files []pd.File) (string, *database.User, error) {
	// Calculate the merkle root with the file digests.
	hashes := make([]*[sha256.Size]byte, 0, len(files))
	for _, v := range files {
		payload, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return "", nil, err
		}

		digest := util.Digest(payload)
		var d [sha256.Size]byte
		copy(d[:], digest)
		hashes = append(hashes, &d)
	}

	var encodedMerkleRoot string
	if len(hashes) > 0 {
		encodedMerkleRoot = hex.EncodeToString(merkle.Root(hashes)[:])
	} else {
		encodedMerkleRoot = ""
	}
	return getSignatureAndSigningUser([]byte(encodedMerkleRoot))
}

func (s *ProposalsTestSuite) verifyProposalDetails(np *www.NewProposal, p www.ProposalRecord) {
	s.Equal(p.Files[0].Payload, np.Files[0].Payload)
}

func (s *ProposalsTestSuite) verifyProposals(p1 www.ProposalRecord, p2 www.ProposalRecord) {
	s.Equal(p1.Name, p2.Name)
	s.Equal(p1.Files[0].Payload, p2.Files[0].Payload)
}

// verifyProposalsSorted verifies that the proposals are returned sorted correctly
func (s *ProposalsTestSuite) verifyProposalsSorted(vettedProposals, unvettedProposals []www.ProposalRecord) {
	allVettedReply := s.backend.ProcessAllVetted(www.GetAllVetted{})
	s.Equal(len(allVettedReply.Proposals), len(vettedProposals))
	for i := 0; i < len(allVettedReply.Proposals); i++ {
		s.verifyProposals(allVettedReply.Proposals[i], vettedProposals[len(allVettedReply.Proposals)-i-1])
	}

	allUnvettedReply := s.backend.ProcessAllUnvetted(www.GetAllUnvetted{})
	s.Equal(len(allUnvettedReply.Proposals), len(unvettedProposals))
	for i := 0; i < len(allUnvettedReply.Proposals); i++ {
		s.verifyProposals(allUnvettedReply.Proposals[i], unvettedProposals[len(allUnvettedReply.Proposals)-i-1])
	}
}
