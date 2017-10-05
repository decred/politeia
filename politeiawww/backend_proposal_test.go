package main

import (
	"encoding/base64"
	"testing"
	"time"

	v1d "github.com/decred/politeia/politeiad/api/v1"
	v1w "github.com/decred/politeia/politeiawww/api/v1"
)

func createNewProposal(b *backend, t *testing.T) (*v1w.NewProposal, *v1w.NewProposalReply, error) {
	return createNewProposalWithFiles(b, t, 1, 0)
}

func createNewProposalWithFiles(b *backend, t *testing.T, numMDFiles, numImageFiles uint) (*v1w.NewProposal, *v1w.NewProposalReply, error) {
	return createNewProposalWithFileSizes(b, t, numMDFiles, numImageFiles, 64, 64)
}

func createNewProposalWithFileSizes(b *backend, t *testing.T, numMDFiles, numImageFiles, mdSize, imageSize uint) (*v1w.NewProposal, *v1w.NewProposalReply, error) {
	files := make([]v1d.File, 0, numMDFiles+numImageFiles)
	for i := uint(0); i < numMDFiles; i++ {
		files = append(files, v1d.File{
			Name:    generateRandomString(5) + ".md",
			MIME:    "text/plain; charset=utf-8",
			Payload: base64.StdEncoding.EncodeToString([]byte(generateRandomString(int(mdSize)))),
		})
	}

	for i := uint(0); i < numImageFiles; i++ {
		files = append(files, v1d.File{
			Name:    generateRandomString(5) + ".png",
			MIME:    "image/png",
			Payload: base64.StdEncoding.EncodeToString([]byte(generateRandomString(int(imageSize)))),
		})
	}

	np := v1w.NewProposal{
		Name:  generateRandomString(16),
		Files: files,
	}

	npr, err := b.ProcessNewProposal(np)
	return &np, npr, err
}

func publishProposal(b *backend, token string, t *testing.T) {
	sps := v1w.SetProposalStatus{
		Token:  token,
		Status: v1d.StatusPublic,
	}
	_, err := b.ProcessSetProposalStatus(sps)
	if err != nil {
		t.Fatal(err)
	}
}

func censorProposal(b *backend, token string, t *testing.T) {
	sps := v1w.SetProposalStatus{
		Token:  token,
		Status: v1d.StatusCensored,
	}
	_, err := b.ProcessSetProposalStatus(sps)
	if err != nil {
		t.Fatal(err)
	}
}

func getProposalDetails(b *backend, token string, t *testing.T) *v1w.ProposalDetailsReply {
	pdr, err := b.ProcessProposalDetails(token)
	if err != nil {
		t.Error(err)
	}

	return pdr
}

func verifyProposalDetails(np *v1w.NewProposal, p v1d.ProposalRecord, t *testing.T) {
	if p.Name != np.Name {
		t.Fatalf("proposal names do not match")
	}
	if p.Files[0].Payload != np.Files[0].Payload {
		t.Fatalf("proposal descriptions do not match")
	}
}

func verifyProposals(p1 v1d.ProposalRecord, p2 v1d.ProposalRecord, t *testing.T) {
	if p1.Name != p2.Name {
		t.Fatalf("proposal names do not match: %v, %v", p1.Name, p2.Name)
	}
	if p1.Files[0].Payload != p2.Files[0].Payload {
		t.Fatalf("proposal descriptions do not match")
	}
}

func verifyProposalsSorted(b *backend, vettedProposals, unvettedProposals []v1d.ProposalRecord, t *testing.T) {
	// Verify that the proposals are returned sorted correctly.
	allVettedReply := b.ProcessAllVetted()
	if len(allVettedReply.Proposals) != len(vettedProposals) {
		t.Fatalf("incorrect number of vetted proposals")
	}
	for i := 0; i < len(allVettedReply.Proposals); i++ {
		verifyProposals(allVettedReply.Proposals[i], vettedProposals[len(allVettedReply.Proposals)-i-1], t)
	}

	allUnvettedReply := b.ProcessAllUnvetted()
	if len(allUnvettedReply.Proposals) != len(unvettedProposals) {
		t.Fatalf("incorrect number of unvetted proposals")
	}
	for i := 0; i < len(allUnvettedReply.Proposals); i++ {
		verifyProposals(allUnvettedReply.Proposals[i], unvettedProposals[len(allUnvettedReply.Proposals)-i-1], t)
	}
}

// Tests the policy restrictions applied when attempting to create a new proposal.
func TestNewProposalPolicyRestrictions(t *testing.T) {
	b := createBackend(t)

	p := b.ProcessPolicy()

	_, npr, err := createNewProposalWithFileSizes(b, t, p.MaxMDs, p.MaxImages, p.MaxMDSize, p.MaxImageSize)
	assertSuccess(t, err, npr.ErrorCode)

	_, npr, err = createNewProposalWithFiles(b, t, p.MaxMDs+1, 0)
	assertError(t, err, npr.ErrorCode, v1w.StatusMaxMDsExceededPolicy)

	_, npr, err = createNewProposalWithFiles(b, t, 1, p.MaxImages+1)
	assertError(t, err, npr.ErrorCode, v1w.StatusMaxImagesExceededPolicy)

	_, npr, err = createNewProposalWithFiles(b, t, 0, 0)
	assertError(t, err, npr.ErrorCode, v1w.StatusProposalMissingDescription)

	_, npr, err = createNewProposalWithFileSizes(b, t, 1, 0, p.MaxMDSize+1, 0)
	assertError(t, err, npr.ErrorCode, v1w.StatusMaxMDSizeExceededPolicy)

	_, npr, err = createNewProposalWithFileSizes(b, t, 1, 1, 64, p.MaxImageSize+1)
	assertError(t, err, npr.ErrorCode, v1w.StatusMaxImageSizeExceededPolicy)
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
	allProposals := make([]v1d.ProposalRecord, 0, 5)
	vettedProposals := make([]v1d.ProposalRecord, 0, 0)
	unvettedProposals := make([]v1d.ProposalRecord, 0, 0)
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
