package main

import (
	"fmt"
	"testing"

	pd "github.com/decred/politeia/politeiad/api/v1"
	www "github.com/decred/politeia/politeiawww/api/v1"
)

func verifyInventoryRecord(ir *inventoryRecord, pr www.ProposalRecord, t *testing.T) {

	// verify record: CensorshipRecord
	err := verifyCensorshipRecord(ir.record.CensorshipRecord, pr.CensorshipRecord)
	if err != nil {
		t.Fatal(err)
	}

	// verify record: Status
	err = verifyStatus(ir.record.Status, pr.Status)
	if err != nil {
		t.Fatal(err)
	}

	// verify record: Files
	err = verifyFiles(ir.record.Files, pr.Files)
	if err != nil {
		t.Fatal(err)
	}

	// verify proposalMD: publickey
	err = verifyPublicKey(ir.proposalMD.PublicKey, pr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
}

func verifyPublicKey(irpk string, prpk string) error {
	if irpk != prpk {
		return fmt.Errorf("Invalid public key, expected %s got %s", prpk, irpk)
	}
	return nil
}

func verifyFiles(irf []pd.File, prf []www.File) error {
	var c, d www.File
	for i, f := range irf {
		c = convertPropFileFromPD(f)
		d = prf[i]
		if c.Digest != d.Digest || c.MIME != d.MIME ||
			c.Name != d.Name || c.Payload != d.Payload {
			return fmt.Errorf("Invalid File, expected %v got %v", d, c)
		}
	}
	return nil
}

func verifyStatus(irs pd.RecordStatusT, prs www.PropStatusT) error {
	c := convertPropStatusFromPD(irs)
	if c != prs {
		return fmt.Errorf("Invalid status, expected %d got %d", prs, c)
	}
	return nil
}

func verifyCensorshipRecord(cr pd.CensorshipRecord, pcr www.CensorshipRecord) error {
	if cr.Token != pcr.Token {
		return fmt.Errorf("Invalid token, expected %s got %s", pcr.Token, cr.Token)
	}

	if cr.Merkle != pcr.Merkle {
		return fmt.Errorf("Invalid Merkle, expected %s got %s", pcr.Merkle, cr.Merkle)
	}

	if cr.Signature != pcr.Signature {
		return fmt.Errorf("Invalid Signature, expected %s got %s", pcr.Signature, cr.Signature)
	}

	return nil
}

// Test creating a proposal and verifying if it was correctly
// added to the inventory
func TestInventoryOnNewProposal(t *testing.T) {
	b := createBackend(t)
	u, id := createAndVerifyUser(t, b)
	user, _ := b.db.UserGet(u.Email)
	_, npr, err := createNewProposal(b, t, user, id)
	if err != nil {
		t.Fatal(err)
	}
	pdr := getProposalDetails(b, npr.CensorshipRecord.Token, t)

	// Verify that inventory has the new record
	ir, ok := b.inventory[npr.CensorshipRecord.Token]
	if !ok {
		t.Fatal("Record not found in the inventory")
	}

	verifyInventoryRecord(ir, pdr.Proposal, t)
}

// Test updating a proposal status by censoring it and verifying if it was
// correctly updated in the inventory
func TestInventoryOnProposalCensored(t *testing.T) {
	b := createBackend(t)
	u, id := createAndVerifyUser(t, b)
	user, _ := b.db.UserGet(u.Email)
	_, npr, err := createNewProposal(b, t, user, id)
	if err != nil {
		t.Fatal(err)
	}

	censorProposal(b, npr.CensorshipRecord.Token, "censor message", t, user, id)
	pdr := getProposalDetails(b, npr.CensorshipRecord.Token, t)

	// Verify that inventory records was updated
	ir, ok := b.inventory[npr.CensorshipRecord.Token]
	if !ok {
		t.Fatal("Record not found in the inventory")
	}

	verifyInventoryRecord(ir, pdr.Proposal, t)
}

func verifyPageLength(page []www.ProposalRecord, expectedLength int) error {
	pageLen := len(page)
	if pageLen != expectedLength {
		return fmt.Errorf("Wrong page length: expected %v, got %v",
			expectedLength, pageLen)
	}
	return nil
}

func TestInventoryPagination(t *testing.T) {
	b := createBackend(t)
	u, id := createAndVerifyUser(t, b)
	user, _ := b.db.UserGet(u.Email)

	pageMaxLen := www.ProposalListPageSize

	// create a number of proposals which we expect to generate
	// 3 full pages and one last page with 2 items
	numOfProposals := (3 * pageMaxLen) + 2
	for i := 0; i < numOfProposals; i++ {
		_, _, err := createNewProposal(b, t, user, id)
		if err != nil {
			t.Fatal(err)
		}
	}

	// make sure all proposals were created
	invLen := len(b.inventory)
	if invLen != numOfProposals {
		t.Fatal("Wrong number of proposals")
	}

	pr := proposalsRequest{
		UserId: user.ID.String(),
		StatusMap: map[www.PropStatusT]bool{
			www.PropStatusNotReviewed: true,
		},
	}

	// get first page
	proposals := b.getProposals(pr)
	loadedProposals := proposals

	// this page should have the max number of items
	err := verifyPageLength(proposals, pageMaxLen)
	if err != nil {
		t.Fatal(err)
	}

	// get second page
	lastProp := proposals[pageMaxLen-1]
	pr.After = lastProp.CensorshipRecord.Token
	proposals = b.getProposals(pr)
	loadedProposals = append(loadedProposals, proposals...)

	// this page should have the max number of items
	err = verifyPageLength(proposals, pageMaxLen)
	if err != nil {
		t.Fatal(err)
	}

	// get third page
	lastProp = proposals[pageMaxLen-1]
	pr.After = lastProp.CensorshipRecord.Token
	proposals = b.getProposals(pr)
	loadedProposals = append(loadedProposals, proposals...)

	// this page should have the max number of items
	err = verifyPageLength(proposals, pageMaxLen)
	if err != nil {
		t.Fatal(err)
	}

	// get fourth page
	lastProp = proposals[pageMaxLen-1]
	pr.After = lastProp.CensorshipRecord.Token
	proposals = b.getProposals(pr)
	loadedProposals = append(loadedProposals, proposals...)

	// this page should have the 2 remaining items
	err = verifyPageLength(proposals, 2)
	if err != nil {
		t.Fatal(err)
	}

	// verify total length of all pages
	err = verifyPageLength(loadedProposals, numOfProposals)
	if err != nil {
		t.Fatal(err)
	}
}
