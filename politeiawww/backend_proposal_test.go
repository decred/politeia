package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"strconv"
	"testing"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
)

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

func createNewProposal(b *backend, t *testing.T) (*www.NewProposal, *www.NewProposalReply, error) {
	return createNewProposalWithFiles(b, t, 1, 0)
}

func createNewProposalWithFiles(b *backend, t *testing.T, numMDFiles, numImageFiles uint) (*www.NewProposal, *www.NewProposalReply, error) {
	return createNewProposalWithFileSizes(b, t, numMDFiles, numImageFiles, 64, 64)
}

func createNewProposalWithFileSizes(b *backend, t *testing.T, numMDFiles, numImageFiles, mdSize, imageSize uint) (*www.NewProposal, *www.NewProposalReply, error) {
	files := make([]pd.File, 0, numMDFiles+numImageFiles)
	var (
		name string
	)

	for i := uint(0); i < numMDFiles; i++ {
		// @rgeraldes - add at least one index file
		if i == 0 {
			name = indexFile
		} else {
			name = generateRandomString(6) + ".md"
		}

		mdSizeWithName := int(mdSize) - len(name) - len("\n")
		payload := []byte(name + "\n" + generateRandomString(mdSizeWithName))

		files = append(files, pd.File{
			Name:    name,
			MIME:    "text/plain; charset=utf-8",
			Payload: base64.StdEncoding.EncodeToString(payload),
		})
	}

	for i := uint(0); i < numImageFiles; i++ {
		name = generateRandomString(5) + ".png"
		imgSizeWithName := int(imageSize) - len(name) - len("\n")
		payload := []byte(name + "\n" + generateRandomString(imgSizeWithName))

		files = append(files, pd.File{
			Name:    name,
			MIME:    "image/png",
			Payload: base64.StdEncoding.EncodeToString(payload),
		})
	}

	signature, user, err := getProposalSignatureAndSigningUser(files)
	if err != nil {
		return nil, nil, err
	}

	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(user.Identities[0].Key[:]),
		Signature: signature,
	}

	npr, err := b.ProcessNewProposal(np, user)
	return &np, npr, err
}

func createNewProposalWithInvalidTitle(b *backend, t *testing.T) (*www.NewProposal, *www.NewProposalReply, error) {
	const (
		invalidTitle = "$%&/)Title<<>>"
	)
	files := make([]pd.File, 0, 2)
	filename := indexFile

	payload := base64.StdEncoding.EncodeToString([]byte(invalidTitle))

	files = append(files, pd.File{
		Name:    filename,
		MIME:    "text/plain; charset=utf-8",
		Payload: payload,
	})

	signature, user, err := getProposalSignatureAndSigningUser(files)
	if err != nil {
		return nil, nil, err
	}

	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(user.Identities[0].Key[:]),
		Signature: signature,
	}

	npr, err := b.ProcessNewProposal(np, user)
	return &np, npr, err
}

func createNewProposalTitleSize(b *backend, t *testing.T, nameLength int) (*www.NewProposal, *www.NewProposalReply, error) {

	invalidTitle := generateRandomString(nameLength)
	files := make([]pd.File, 0, 2)
	filename := indexFile

	payload := base64.StdEncoding.EncodeToString([]byte(invalidTitle))

	files = append(files, pd.File{
		Name:    filename,
		MIME:    "text/plain; charset=utf-8",
		Payload: payload,
	})

	signature, user, err := getProposalSignatureAndSigningUser(files)
	if err != nil {
		return nil, nil, err
	}

	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(user.Identities[0].Key[:]),
		Signature: signature,
	}

	npr, err := b.ProcessNewProposal(np, user)
	return &np, npr, err
}

func createNewProposalWithDuplicateFiles(b *backend, t *testing.T) (*www.NewProposal, *www.NewProposalReply, error) {
	files := make([]pd.File, 0, 2)
	filename := indexFile
	payload := base64.StdEncoding.EncodeToString([]byte(generateRandomString(int(64))))

	files = append(files, pd.File{
		Name:    filename,
		MIME:    "text/plain; charset=utf-8",
		Payload: payload,
	})

	files = append(files, pd.File{
		Name:    filename,
		MIME:    "text/plain; charset=utf-8",
		Payload: payload,
	})

	signature, user, err := getProposalSignatureAndSigningUser(files)
	if err != nil {
		return nil, nil, err
	}

	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(user.Identities[0].Key[:]),
		Signature: signature,
	}

	npr, err := b.ProcessNewProposal(np, user)
	return &np, npr, err
}

func createNewProposalWithoutIndexFile(b *backend, t *testing.T) (*www.NewProposal, *www.NewProposalReply, error) {
	files := make([]pd.File, 0, 2)

	files = append(files, pd.File{
		Name:    "not_index.md",
		MIME:    "text/plain; charset=utf-8",
		Payload: base64.StdEncoding.EncodeToString([]byte(generateRandomString(int(64)))),
	})

	signature, user, err := getProposalSignatureAndSigningUser(files)
	if err != nil {
		return nil, nil, err
	}

	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(user.Identities[0].Key[:]),
		Signature: signature,
	}

	npr, err := b.ProcessNewProposal(np, user)
	return &np, npr, err
}

func publishProposal(b *backend, token string, t *testing.T) {
	sps := www.SetProposalStatus{
		Token:          token,
		ProposalStatus: www.PropStatusPublic,
	}

	msg := sps.Token + strconv.FormatUint(uint64(sps.ProposalStatus), 10)
	signature, user, err := getSignatureAndSigningUser([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	sps.Signature = signature

	_, err = b.ProcessSetProposalStatus(sps, user)
	if err != nil {
		t.Fatal(err)
	}
}

func censorProposal(b *backend, token string, t *testing.T) {
	sps := www.SetProposalStatus{
		Token:          token,
		ProposalStatus: www.PropStatusCensored,
	}

	msg := sps.Token + strconv.FormatUint(uint64(sps.ProposalStatus), 10)
	signature, user, err := getSignatureAndSigningUser([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	sps.Signature = signature

	_, err = b.ProcessSetProposalStatus(sps, user)
	if err != nil {
		t.Fatal(err)
	}
}

func getProposalDetails(b *backend, token string, t *testing.T) *www.ProposalDetailsReply {
	pd := www.ProposalsDetails{
		Token: token,
	}
	pdr, err := b.ProcessProposalDetails(pd, true)
	if err != nil {
		t.Error(err)
	}

	return pdr
}

func verifyProposalDetails(np *www.NewProposal, p www.ProposalRecord, t *testing.T) {
	if p.Files[0].Payload != np.Files[0].Payload {
		t.Fatalf("proposal descriptions do not match")
	}
}

func verifyProposals(p1 www.ProposalRecord, p2 www.ProposalRecord, t *testing.T) {
	if p1.Name != p2.Name {
		t.Fatalf("proposal names do not match: %v, %v", p1.Name, p2.Name)
	}
	if p1.Files[0].Payload != p2.Files[0].Payload {
		t.Fatalf("proposal descriptions do not match")
	}
}

func verifyProposalsSorted(b *backend, vettedProposals, unvettedProposals []www.ProposalRecord, t *testing.T) {
	// Verify that the proposals are returned sorted correctly.
	allVettedReply := b.ProcessAllVetted(www.GetAllVetted{})
	if len(allVettedReply.Proposals) != len(vettedProposals) {
		t.Fatalf("incorrect number of vetted proposals")
	}
	for i := 0; i < len(allVettedReply.Proposals); i++ {
		verifyProposals(allVettedReply.Proposals[i],
			vettedProposals[len(allVettedReply.Proposals)-i-1], t)
	}

	allUnvettedReply := b.ProcessAllUnvetted(www.GetAllUnvetted{})
	if len(allUnvettedReply.Proposals) != len(unvettedProposals) {
		t.Fatalf("incorrect number of unvetted proposals")
	}
	for i := 0; i < len(allUnvettedReply.Proposals); i++ {
		verifyProposals(allUnvettedReply.Proposals[i],
			unvettedProposals[len(allUnvettedReply.Proposals)-i-1], t)
	}
}

// Tests the policy restrictions applied when attempting to create a new proposal.
func TestNewProposalPolicyRestrictions(t *testing.T) {
	b := createBackend(t)

	p := b.ProcessPolicy(www.Policy{})

	_, _, err := createNewProposalWithFileSizes(b, t, p.MaxMDs, p.MaxImages, p.MaxMDSize, p.MaxImageSize)
	assertSuccess(t, err)

	_, _, err = createNewProposalWithFiles(b, t, p.MaxMDs+1, 0)
	assertError(t, err, www.ErrorStatusMaxMDsExceededPolicy)

	_, _, err = createNewProposalWithFiles(b, t, 1, p.MaxImages+1)
	assertError(t, err, www.ErrorStatusMaxImagesExceededPolicy)

	_, _, err = createNewProposalWithFiles(b, t, 0, 0)
	assertError(t, err, www.ErrorStatusProposalMissingFiles)

	_, _, err = createNewProposalWithFileSizes(b, t, 1, 0, p.MaxMDSize+1, 0)
	assertError(t, err, www.ErrorStatusMaxMDSizeExceededPolicy)

	_, _, err = createNewProposalWithFileSizes(b, t, 1, 1, 64, p.MaxImageSize+1)
	assertError(t, err, www.ErrorStatusMaxImageSizeExceededPolicy)

	_, _, err = createNewProposalWithInvalidTitle(b, t)
	assertErrorWithContext(t, err, www.ErrorStatusProposalInvalidTitle, []string{util.CreateProposalTitleRegex()})

	_, _, err = createNewProposalTitleSize(b, t, www.PolicyMaxProposalNameLength+1)
	assertErrorWithContext(t, err, www.ErrorStatusProposalInvalidTitle, []string{util.CreateProposalTitleRegex()})

	_, _, err = createNewProposalTitleSize(b, t, www.PolicyMinProposalNameLength-1)
	assertErrorWithContext(t, err, www.ErrorStatusProposalInvalidTitle, []string{util.CreateProposalTitleRegex()})

	_, _, err = createNewProposalWithDuplicateFiles(b, t)
	assertErrorWithContext(t, err, www.ErrorStatusProposalDuplicateFilenames, []string{indexFile})

	_, _, err = createNewProposalWithoutIndexFile(b, t)
	assertErrorWithContext(t, err, www.ErrorStatusProposalMissingFiles, []string{indexFile})
}

// Tests creates a new proposal with an invalid signature.
func TestNewProposalWithInvalidSignature(t *testing.T) {
	b := createBackend(t)

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
	if err != nil {
		t.Fatal(err)
	}

	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(user.Identities[0].Key[:]),
		Signature: signature,
	}

	_, err = b.ProcessNewProposal(np, user)
	assertError(t, err, www.ErrorStatusInvalidSignature)

	b.db.Close()
}

// Tests creates a new proposal with an invalid signature.
func TestNewProposalWithInvalidSigningKey(t *testing.T) {
	b := createBackend(t)

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
	if err != nil {
		t.Fatal(err)
	}

	alternateId, err := generateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	np := www.NewProposal{
		Files:     convertPropFilesFromPD(files),
		PublicKey: hex.EncodeToString(alternateId.Public.Key[:]),
		Signature: signature,
	}

	_, err = b.ProcessNewProposal(np, user)
	assertError(t, err, www.ErrorStatusInvalidSigningKey)

	b.db.Close()
}

// Tests fetching an unreviewed proposal's details.
func TestUnreviewedProposal(t *testing.T) {
	b := createBackend(t)
	np, npr, err := createNewProposal(b, t)
	if err != nil {
		t.Fatal(err)
	}
	pdr := getProposalDetails(b, npr.CensorshipRecord.Token, t)
	verifyProposalDetails(np, pdr.Proposal, t)

	b.db.Close()
}

// Tests censoring a proposal and then fetching its details.
func TestCensoredProposal(t *testing.T) {
	b := createBackend(t)
	np, npr, err := createNewProposal(b, t)
	if err != nil {
		t.Fatal(err)
	}
	censorProposal(b, npr.CensorshipRecord.Token, t)
	pdr := getProposalDetails(b, npr.CensorshipRecord.Token, t)
	verifyProposalDetails(np, pdr.Proposal, t)

	b.db.Close()
}

// Tests publishing a proposal and then fetching its details.
func TestPublishedProposal(t *testing.T) {
	b := createBackend(t)
	np, npr, err := createNewProposal(b, t)
	if err != nil {
		t.Fatal(err)
	}
	publishProposal(b, npr.CensorshipRecord.Token, t)
	pdr := getProposalDetails(b, npr.CensorshipRecord.Token, t)
	verifyProposalDetails(np, pdr.Proposal, t)

	b.db.Close()
}

// Tests that the inventory is always sorted by timestamp.
func TestInventorySorted(t *testing.T) {
	b := createBackend(t)

	// Create an array of proposals, some vetted and some unvetted.
	allProposals := make([]www.ProposalRecord, 0, 5)
	vettedProposals := make([]www.ProposalRecord, 0)
	unvettedProposals := make([]www.ProposalRecord, 0)
	for i := 0; i < cap(allProposals); i++ {
		_, npr, err := createNewProposal(b, t)
		if err != nil {
			t.Fatal(err)
		}

		if i%2 == 0 {
			publishProposal(b, npr.CensorshipRecord.Token, t)
		}

		pdr := getProposalDetails(b, npr.CensorshipRecord.Token, t)
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
	verifyProposalsSorted(b, vettedProposals, unvettedProposals, t)

	// Wipe the inventory and fetch it again.
	err := b.LoadInventory()
	if err != nil {
		t.Fatal(err)
	}

	/*
		fmt.Printf("\nInventory:\n")
		for _, v := range b.inventory {
			fmt.Printf("%v %v %v\n", v.Name, v.Status, v.Timestamp)
		}
	*/

	// Verify that the proposals are still sorted correctly.
	verifyProposalsSorted(b, vettedProposals, unvettedProposals, t)

	b.db.Close()
}

func TestProposalListPaging(t *testing.T) {
	b := createBackend(t)

	tokens := make([]string, www.ProposalListPageSize+1)
	for i := 0; i < www.ProposalListPageSize+1; i++ {
		_, npr, err := createNewProposal(b, t)
		if err != nil {
			t.Fatal(err)
		}

		tokens[i] = npr.CensorshipRecord.Token
	}

	var u www.GetAllUnvetted
	ur := b.ProcessAllUnvetted(u)
	if len(ur.Proposals) != www.ProposalListPageSize {
		t.Fatalf("expected %v proposals, got %v", www.ProposalListPageSize,
			len(ur.Proposals))
	}

	// Test fetching the next page using the After field.
	u.After = ur.Proposals[len(ur.Proposals)-1].CensorshipRecord.Token
	ur = b.ProcessAllUnvetted(u)
	if len(ur.Proposals) != 1 {
		t.Fatalf("expected 1 proposal, got %v", len(ur.Proposals))
	}
	for _, v := range ur.Proposals {
		if v.CensorshipRecord.Token == u.After {
			t.Fatalf("Proposal with token provided for 'After' field should " +
				"not exist in the next page")
		}
	}

	// Test fetching the previous page using the Before field.
	u.After = ""
	u.Before = ur.Proposals[0].CensorshipRecord.Token
	ur = b.ProcessAllUnvetted(u)
	if len(ur.Proposals) != www.ProposalListPageSize {
		t.Fatalf("expected %v proposals, got %v", www.ProposalListPageSize,
			len(ur.Proposals))
	}
	for _, v := range ur.Proposals {
		if v.CensorshipRecord.Token == u.Before {
			t.Fatalf("Proposal with token provided for 'Before' field should " +
				"not exist in the previous page")
		}
	}

	// Publish all the proposals.
	for _, token := range tokens {
		publishProposal(b, token, t)
	}

	var v www.GetAllVetted
	vr := b.ProcessAllVetted(v)
	if len(vr.Proposals) != www.ProposalListPageSize {
		t.Fatalf("expected %v proposals, got %v", www.ProposalListPageSize,
			len(vr.Proposals))
	}

	// Test fetching the next page using the After field.
	v.After = vr.Proposals[len(vr.Proposals)-1].CensorshipRecord.Token
	vr = b.ProcessAllVetted(v)
	if len(vr.Proposals) != 1 {
		t.Fatalf("expected 1 proposal, got %v", len(vr.Proposals))
	}

	// Test fetching the previous page using the Before field.
	v.After = ""
	v.Before = vr.Proposals[0].CensorshipRecord.Token
	vr = b.ProcessAllVetted(v)
	if len(vr.Proposals) != www.ProposalListPageSize {
		t.Fatalf("expected %v proposals, got %v", www.ProposalListPageSize,
			len(vr.Proposals))
	}

	b.db.Close()
}
