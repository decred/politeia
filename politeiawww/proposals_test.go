// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/testpoliteiad"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	www2 "github.com/decred/politeia/politeiawww/api/www/v2"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

func proposalNameRandom(t *testing.T) string {
	r, err := util.Random(www.PolicyMinProposalNameLength)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(r)
}

// merkleRoot returns a hex encoded merkle root of the passed in files and
// metadata.
func merkleRoot(t *testing.T, files []www.File, metadata []www.Metadata) string {
	t.Helper()

	digests := make([]*[sha256.Size]byte, 0, len(files))
	for _, f := range files {
		// Compute file digest
		b, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			t.Fatalf("decode payload for file %v: %v",
				f.Name, err)
		}
		digest := util.Digest(b)

		// Compare against digest that came with the file
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			t.Fatalf("invalid digest: file:%v digest:%v",
				f.Name, f.Digest)
		}
		if !bytes.Equal(digest, d[:]) {
			t.Fatalf("digests do not match for file %v",
				f.Name)
		}

		// Digest is valid
		digests = append(digests, &d)
	}

	for _, v := range metadata {
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			t.Fatalf("decode payload for metadata %v: %v",
				v.Hint, err)
		}
		digest := util.Digest(b)
		d, ok := util.ConvertDigest(v.Digest)
		if !ok {
			t.Fatalf("invalid digest: metadata:%v digest:%v",
				v.Hint, v.Digest)
		}
		if !bytes.Equal(digest, d[:]) {
			t.Fatalf("digests do not match for metadata %v",
				v.Hint)
		}

		// Digest is valid
		digests = append(digests, &d)
	}

	// Compute merkle root
	return hex.EncodeToString(merkle.Root(digests)[:])
}

// createFilePNG creates a File that contains a png image.  The png image is
// blank by default but can be filled in with random rgb colors by setting the
// addColor parameter to true.  The png without color will be ~3kB.  The png
// with color will be ~2MB.
func createFilePNG(t *testing.T, addColor bool) *www.File {
	t.Helper()

	b := new(bytes.Buffer)
	img := image.NewRGBA(image.Rect(0, 0, 1000, 500))

	// Fill in the pixels with random rgb colors in order to
	// increase the size of the image. This is used to create an
	// image that exceeds the maximum image size policy.
	if addColor {
		r := rand.New(rand.NewSource(255))
		for y := 0; y < img.Bounds().Max.Y-1; y++ {
			for x := 0; x < img.Bounds().Max.X-1; x++ {
				a := uint8(r.Float32() * 255)
				rgb := uint8(r.Float32() * 255)
				img.SetRGBA(x, y, color.RGBA{rgb, rgb, rgb, a})
			}
		}
	}

	err := png.Encode(b, img)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Generate a random name
	r, err := util.Random(8)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return &www.File{
		Name:    hex.EncodeToString(r) + ".png",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}
}

// createFileMD creates a File that contains a markdown file.  The markdown
// file is filled with randomly generated data.
func createFileMD(t *testing.T, size int) *www.File {
	t.Helper()

	var b bytes.Buffer
	r, err := util.Random(size)
	if err != nil {
		t.Fatalf("%v", err)
	}
	b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")

	return &www.File{
		Name:    www.PolicyIndexFilename,
		MIME:    http.DetectContentType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}
}

// createNewProposal computes the merkle root of the given files, signs the
// merkle root with the given identity then returns a NewProposal object.
func createNewProposal(t *testing.T, id *identity.FullIdentity, files []www.File, title string) *www.NewProposal {
	t.Helper()

	// Setup metadata
	metadata, _ := newProposalMetadata(t, title, "", 0)

	// Compute and sign merkle root
	m := merkleRoot(t, files, metadata)
	sig := id.SignMessage([]byte(m))

	return &www.NewProposal{
		Files:     files,
		Metadata:  metadata,
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}
}

// newFileRandomMD returns a File with the name index.md that contains random
// base64 text.
func newFileRandomMD(t *testing.T) www.File {
	t.Helper()

	var b bytes.Buffer
	// Add ten lines of random base64 text.
	for i := 0; i < 10; i++ {
		r, err := util.Random(32)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")
	}

	return www.File{
		Name:    "index.md",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}
}

func newStartVote(t *testing.T, token string, proposalVersion uint32, id *identity.FullIdentity) www2.StartVote {
	vote := www2.Vote{
		Token:            token,
		ProposalVersion:  proposalVersion,
		Type:             www2.VoteTypeStandard,
		Mask:             0x03, // bit 0 no, bit 1 yes
		Duration:         2016,
		QuorumPercentage: 20,
		PassPercentage:   60,
		Options: []www2.VoteOption{
			{
				Id:          "no",
				Description: "Don't approve proposal",
				Bits:        0x01,
			},
			{
				Id:          "yes",
				Description: "Approve proposal",
				Bits:        0x02,
			},
		},
	}
	vb, err := json.Marshal(vote)
	if err != nil {
		t.Fatalf("marshal vote failed: %v %v", err, vote)
	}
	msg := hex.EncodeToString(util.Digest(vb))
	sig := id.SignMessage([]byte(msg))
	return www2.StartVote{
		Vote:      vote,
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}
}

func newStartVoteCmd(t *testing.T, token string, proposalVersion uint32, id *identity.FullIdentity) pd.PluginCommand {
	sv := newStartVote(t, token, proposalVersion, id)
	dsv := convertStartVoteV2ToDecred(sv)
	payload, err := decredplugin.EncodeStartVoteV2(dsv)
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		t.Fatal(err)
	}

	return pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdStartVote,
		CommandID: decredplugin.CmdStartVote + " " + sv.Vote.Token,
		Payload:   string(payload),
	}
}

func newAuthorizeVote(token, version, action string, id *identity.FullIdentity) www.AuthorizeVote {
	sig := id.SignMessage([]byte(token + version + action))
	return www.AuthorizeVote{
		Action:    action,
		Token:     token,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}
}

func newAuthorizeVoteCmd(t *testing.T, token, version, action string, id *identity.FullIdentity) pd.PluginCommand {
	av := newAuthorizeVote(token, version, action, id)
	dav := convertAuthorizeVoteToDecred(av)
	payload, err := decredplugin.EncodeAuthorizeVote(dav)
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		t.Fatal(err)
	}

	return pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdAuthorizeVote,
		CommandID: decredplugin.CmdAuthorizeVote + " " + av.Token,
		Payload:   string(payload),
	}
}

func newProposalRecord(t *testing.T, u *user.User, id *identity.FullIdentity, s www.PropStatusT) www.ProposalRecord {
	t.Helper()

	f := newFileRandomMD(t)
	files := []www.File{f}
	name := proposalNameRandom(t)
	metadata, _ := newProposalMetadata(t, name, "", 0)
	m := merkleRoot(t, files, metadata)
	sig := id.SignMessage([]byte(m))

	var (
		publishedAt int64
		censoredAt  int64
		abandonedAt int64
		changeMsg   string
	)

	switch s {
	case www.PropStatusCensored:
		changeMsg = "did not adhere to guidelines"
		censoredAt = time.Now().Unix()
	case www.PropStatusPublic:
		publishedAt = time.Now().Unix()
	case www.PropStatusAbandoned:
		changeMsg = "no activity"
		publishedAt = time.Now().Unix()
		abandonedAt = time.Now().Unix()
	}

	tokenb, err := util.Random(pd.TokenSize)
	if err != nil {
		t.Fatal(err)
	}

	// The token is typically generated in politeiad. This function
	// generates the token locally to make setting up tests easier.
	// The censorship record signature is left intentionally blank.
	return www.ProposalRecord{
		Name:                name,
		State:               convertPropStatusToState(s),
		Status:              s,
		Timestamp:           time.Now().Unix(),
		UserId:              u.ID.String(),
		Username:            u.Username,
		PublicKey:           u.PublicKey(),
		Signature:           hex.EncodeToString(sig[:]),
		NumComments:         0,
		Version:             "1",
		StatusChangeMessage: changeMsg,
		PublishedAt:         publishedAt,
		CensoredAt:          censoredAt,
		AbandonedAt:         abandonedAt,
		Files:               files,
		Metadata:            metadata,
		CensorshipRecord: www.CensorshipRecord{
			Token:     hex.EncodeToString(tokenb),
			Merkle:    m,
			Signature: "",
		},
	}
}

func newProposalMetadata(t *testing.T, name, linkto string, linkby int64) ([]www.Metadata, www.ProposalMetadata) {
	if name == "" {
		// Generate a random name if none was given
		name = proposalNameRandom(t)
	}
	pm := www.ProposalMetadata{
		Name:   name,
		LinkTo: linkto,
		LinkBy: linkby,
	}
	pmb, err := json.Marshal(pm)
	if err != nil {
		t.Fatal(err)
	}
	md := []www.Metadata{
		{
			Digest:  hex.EncodeToString(util.Digest(pmb)),
			Hint:    www.HintProposalMetadata,
			Payload: base64.StdEncoding.EncodeToString(pmb),
		},
	}
	return md, pm
}

func newVoteSummary(t *testing.T, s www.PropVoteStatusT, rs []www.VoteOptionResult) www.VoteSummary {
	t.Helper()

	return www.VoteSummary{
		Status:           s,
		EligibleTickets:  10,
		QuorumPercentage: 30,
		PassPercentage:   60,
		Results:          rs,
	}
}

func newVoteOptionResult(t *testing.T, id, desc string, bits, votes uint64) www.VoteOptionResult {
	t.Helper()

	return www.VoteOptionResult{
		Option: www.VoteOption{
			Id:          id,
			Description: desc,
			Bits:        bits,
		},
		VotesReceived: votes,
	}
}

func makeProposalRFP(t *testing.T, pr *www.ProposalRecord, linkedfrom []string, linkby int64) {
	t.Helper()

	md, _ := newProposalMetadata(t, pr.Name, "", linkby)
	pr.LinkBy = linkby
	pr.LinkedFrom = linkedfrom
	pr.Metadata = md
}

func makeProposalRFPSubmissions(t *testing.T, prs []*www.ProposalRecord, linkto string) {
	t.Helper()
	for _, pr := range prs {
		md, _ := newProposalMetadata(t, pr.Name, linkto, 0)
		pr.LinkTo = linkto
		pr.Metadata = md
	}
}

func convertPropToPD(t *testing.T, p www.ProposalRecord) pd.Record {
	t.Helper()

	// Attach ProposalMetadata as a politeiad file
	files := convertPropFilesFromWWW(p.Files)
	for _, v := range p.Metadata {
		switch v.Hint {
		case www.HintProposalMetadata:
			files = append(files, convertFileFromMetadata(v))
		}
	}

	// Create a ProposalGeneralV2 mdstream
	md, err := mdstream.EncodeProposalGeneralV2(
		mdstream.ProposalGeneralV2{
			Version:   mdstream.VersionProposalGeneral,
			Timestamp: time.Now().Unix(),
			PublicKey: p.PublicKey,
			Signature: p.Signature,
		})
	if err != nil {
		t.Fatal(err)
	}

	mdStreams := []pd.MetadataStream{{
		ID:      mdstream.IDProposalGeneral,
		Payload: string(md),
	}}

	return pd.Record{
		Status:           convertPropStatusFromWWW(p.Status),
		Timestamp:        p.Timestamp,
		Version:          p.Version,
		Metadata:         mdStreams,
		CensorshipRecord: convertPropCensorFromWWW(p.CensorshipRecord),
		Files:            files,
	}
}

func TestIsValidProposalName(t *testing.T) {
	tests := []struct {
		name string // @rgeraldes - valid input is a string without new lines
		want bool
	}{
		// empty test
		{
			"",
			false,
		},
		// 7 characters
		{
			"abcdefg",
			false,
		},

		// 81 characters
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			false,
		},
		// 8 characters
		{
			"12345678",
			true,
		},
		{
			"valid title",
			true,
		},
		{
			" - title: is valid; title. !.,  ",
			true,
		},
		{
			" - title: is valid; title.   ",
			true,
		},
		{
			"\n\n#This-is MY tittle###",
			false,
		},
		{
			"{this-is-the-title}",
			false,
		},
		{
			"\t<this- is-the title>",
			false,
		},
		{
			"{this   -is-the-title}   ",
			false,
		},
		{
			"###this is the title***",
			false,
		},
		{
			"###this is the title@+",
			true,
		},
	}

	for _, test := range tests {
		isValid := isValidProposalName(test.name)
		if isValid != test.want {
			t.Errorf("got %v, want %v", isValid, test.want)
		}
	}
}

func TestIsProposalAuthor(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	usr, id := newUser(t, p, true, false)
	notAuthorUser, _ := newUser(t, p, true, false)

	proposal := newProposalRecord(t, usr, id, www.PropStatusPublic)

	var tests = []struct {
		name     string
		proposal www.ProposalRecord
		usr      *user.User
		want     bool
	}{
		{
			"is proposal author",
			proposal,
			usr,
			true,
		},
		{
			"is not proposal author",
			proposal,
			notAuthorUser,
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isAuthor := isProposalAuthor(test.proposal, *test.usr)
			if isAuthor != test.want {
				t.Errorf("got %v, want %v", isAuthor, test.want)
			}
		})
	}
}

func TestIsRFP(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	usr, id := newUser(t, p, true, false)

	rfpProposal := newProposalRecord(t, usr, id, www.PropStatusPublic)
	rfpProposalSubmission := newProposalRecord(t, usr, id, www.PropStatusPublic)

	linkFrom := []string{rfpProposalSubmission.CensorshipRecord.Token}
	linkTo := rfpProposal.CensorshipRecord.Token
	linkBy := time.Now().Add(time.Hour * 24 * 30).Unix()

	rfpSubmissions := []*www.ProposalRecord{&rfpProposalSubmission}

	makeProposalRFP(t, &rfpProposal, linkFrom, linkBy)
	makeProposalRFPSubmissions(t, rfpSubmissions, linkTo)

	var tests = []struct {
		name     string
		proposal www.ProposalRecord
		want     bool
	}{
		{
			"is RFP proposal",
			rfpProposal,
			true,
		},
		{
			"is not RFP proposal",
			rfpProposalSubmission,
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isRFP := isRFP(test.proposal)
			if isRFP != test.want {
				t.Errorf("got %v, want %v", isRFP, test.want)
			}
		})
	}
}

func TestIsRFPSubmission(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	usr, id := newUser(t, p, true, false)

	rfpProposal := newProposalRecord(t, usr, id, www.PropStatusPublic)
	rfpProposalSubmission := newProposalRecord(t, usr, id, www.PropStatusPublic)

	linkFrom := []string{rfpProposalSubmission.CensorshipRecord.Token}
	linkTo := rfpProposal.CensorshipRecord.Token
	linkBy := time.Now().Add(time.Hour * 24 * 30).Unix()
	rfpSubmissions := []*www.ProposalRecord{&rfpProposalSubmission}

	makeProposalRFP(t, &rfpProposal, linkFrom, linkBy)
	makeProposalRFPSubmissions(t, rfpSubmissions, linkTo)

	var tests = []struct {
		name     string
		proposal www.ProposalRecord
		want     bool
	}{
		{
			"is RFP submission",
			rfpProposalSubmission,
			true,
		},
		{
			"is not RFP submission",
			rfpProposal,
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isRFPSubmission := isRFPSubmission(test.proposal)
			if isRFPSubmission != test.want {
				t.Errorf("got %v, want %v", isRFPSubmission, test.want)
			}
		})
	}
}

func TestVoteIsApproved(t *testing.T) {
	yes := decredplugin.VoteOptionIDApprove
	no := decredplugin.VoteOptionIDReject
	emptyResults := []www.VoteOptionResult{}
	badQuorumResults := []www.VoteOptionResult{
		newVoteOptionResult(t, no, "not approve", 1, 0),
		newVoteOptionResult(t, yes, "approve", 2, 1),
	}
	badPassPercentageResults := []www.VoteOptionResult{
		newVoteOptionResult(t, no, "not approve", 1, 8),
		newVoteOptionResult(t, yes, "approve", 2, 2),
	}
	approvedResults := []www.VoteOptionResult{
		newVoteOptionResult(t, no, "not approve", 1, 2),
		newVoteOptionResult(t, yes, "approve", 2, 8),
	}
	vsVoteNotFinished :=
		newVoteSummary(t, www.PropVoteStatusAuthorized, emptyResults)
	vsQuorumNotMet :=
		newVoteSummary(t, www.PropVoteStatusFinished, badQuorumResults)
	vsPassPercentageNotMet :=
		newVoteSummary(t, www.PropVoteStatusFinished, badPassPercentageResults)
	vsApproved :=
		newVoteSummary(t, www.PropVoteStatusFinished, approvedResults)

	var tests = []struct {
		name    string
		summary www.VoteSummary
		want    bool
	}{
		{
			"vote not finished",
			vsVoteNotFinished,
			false,
		},
		{
			"vote did not pass quorum",
			vsQuorumNotMet,
			false,
		},
		{
			"vote did not meet pass percentage",
			vsPassPercentageNotMet,
			false,
		},
		{
			"vote is approved",
			vsApproved,
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := voteIsApproved(test.summary)
			if got != test.want {
				t.Errorf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestValidateProposalMetadata(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	d := newTestPoliteiad(t, p)
	defer d.Close()

	usr, id := newUser(t, p, true, false)

	// Helper variables
	no := decredplugin.VoteOptionIDReject
	yes := decredplugin.VoteOptionIDApprove
	public := www.PropStatusPublic
	linkFrom := []string{}
	linkBy := time.Now().Add(time.Hour * 24 * 30).Unix()
	invalidName := "bad"
	validName := "valid name"
	invalidToken := "abcdfe"
	randomToken, err := util.Random(pd.TokenSize)
	if err != nil {
		t.Fatal(err)
	}
	rToken := hex.EncodeToString(randomToken)

	// Public proposal
	proposal := newProposalRecord(t, usr, id, public)
	token := proposal.CensorshipRecord.Token
	d.AddRecord(t, convertPropToPD(t, proposal))

	// RFP proposal approved
	rfpProposal := newProposalRecord(t, usr, id, public)
	rfpToken := rfpProposal.CensorshipRecord.Token
	makeProposalRFP(t, &rfpProposal, linkFrom, linkBy)
	d.AddRecord(t, convertPropToPD(t, rfpProposal))

	// RFP proposal not approved
	rfpProposalNotApproved := newProposalRecord(t, usr, id, public)
	rfpTokenNotApproved := rfpProposalNotApproved.CensorshipRecord.Token
	makeProposalRFP(t, &rfpProposalNotApproved, linkFrom, linkBy)
	d.AddRecord(t, convertPropToPD(t, rfpProposalNotApproved))

	// RFP bad linkBy expired timestamp
	rfpBadLinkBy := newProposalRecord(t, usr, id, public)
	rfpBadLinkByToken := rfpBadLinkBy.CensorshipRecord.Token
	badLinkBy := int64(1351700038)
	makeProposalRFP(t, &rfpBadLinkBy, linkFrom, badLinkBy)
	d.AddRecord(t, convertPropToPD(t, rfpBadLinkBy))

	// RFP bad state
	rfpBadState := newProposalRecord(t, usr, id, www.PropStatusNotReviewed)
	rfpBadStateToken := rfpBadState.CensorshipRecord.Token
	makeProposalRFP(t, &rfpBadState, linkFrom, linkBy)
	d.AddRecord(t, convertPropToPD(t, rfpBadState))

	// Approved VoteSummary for proposal
	approved := []www.VoteOptionResult{
		newVoteOptionResult(t, no, "not approve", 1, 2),
		newVoteOptionResult(t, yes, "approve", 2, 8),
	}
	vsApproved := newVoteSummary(t, www.PropVoteStatusFinished, approved)
	p.voteSummarySet(rfpToken, vsApproved)
	p.voteSummarySet(rfpBadLinkByToken, vsApproved)

	// Not approved VoteSummary for proposal
	notApproved := []www.VoteOptionResult{
		newVoteOptionResult(t, no, "not approve", 1, 8),
		newVoteOptionResult(t, yes, "approve", 2, 2),
	}
	vsNotApproved := newVoteSummary(t, www.PropVoteStatusFinished, notApproved)
	p.voteSummarySet(rfpTokenNotApproved, vsNotApproved)
	p.voteSummarySet(rfpBadLinkByToken, vsApproved)
	p.voteSummarySet(rfpBadStateToken, vsApproved)

	// Metadatas to validate and test
	_, mdInvalidName := newProposalMetadata(t, invalidName, "", 0)
	// LinkTo validations
	_, mdInvalidLinkTo := newProposalMetadata(t, validName, invalidToken, 0)
	_, mdProposalNotFound := newProposalMetadata(t, validName, rToken, 0)
	_, mdProposalNotRFP := newProposalMetadata(t, validName, token, 0)
	_, mdProposalNotApproved :=
		newProposalMetadata(t, validName, rfpTokenNotApproved, 0)
	_, mdProposalBadLinkBy :=
		newProposalMetadata(t, validName, rfpBadLinkByToken, 0)
	_, mdProposalBadState :=
		newProposalMetadata(t, validName, rfpBadStateToken, 0)
	_, mdProposalBothRFP :=
		newProposalMetadata(t, validName, rfpToken, time.Now().Unix())
	// LinkBy validations
	_, mdLinkByMin :=
		newProposalMetadata(t, validName, "", 100)
	_, mdLinkByMax :=
		newProposalMetadata(t, validName, "", time.Now().Unix()+7777000)
	linkByMinError :=
		fmt.Sprintf("linkby period cannot be shorter than %v seconds",
			p.linkByPeriodMin())
	linkByMaxError :=
		fmt.Sprintf("linkby period cannot be greater than %v seconds",
			p.linkByPeriodMax())
	_, mdSuccess :=
		newProposalMetadata(t, validName, rfpToken, 0)

	var tests = []struct {
		name      string
		metadata  www.ProposalMetadata
		wantError error
	}{
		{
			"invalid proposal name",
			mdInvalidName,
			www.UserError{
				ErrorCode:    www.ErrorStatusProposalInvalidTitle,
				ErrorContext: []string{createProposalNameRegex()},
			},
		},
		{
			"invalid linkTo bad token",
			mdInvalidLinkTo,
			www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"invalid token"},
			},
		},
		{
			"invalid linkTo proposal token not found",
			mdProposalNotFound,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidLinkTo,
			},
		},
		{
			"invalid linkTo not a RFP proposal",
			mdProposalNotRFP,
			www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"linkto proposal is not an rfp"},
			},
		},
		{
			"invalid linkTo RFP proposal vote not approved",
			mdProposalNotApproved,
			www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"rfp proposal vote did not pass"},
			},
		},
		{
			"invalid linkTo proposal deadline is expired",
			mdProposalBadLinkBy,
			www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"linkto proposal deadline is expired"},
			},
		},
		{
			"invalid linkTo proposal is not vetted",
			mdProposalBadState,
			www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"linkto proposal is not vetted"},
			},
		},
		{
			"invalid linkTo rfp proposal linked to another rfp",
			mdProposalBothRFP,
			www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkTo,
				ErrorContext: []string{"an rfp cannot link to an rfp"},
			},
		},
		{
			"invalid linkBy shorter than min",
			mdLinkByMin,
			www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkBy,
				ErrorContext: []string{linkByMinError},
			},
		}, {
			"invalid linkBy greather than max",
			mdLinkByMax,
			www.UserError{
				ErrorCode:    www.ErrorStatusInvalidLinkBy,
				ErrorContext: []string{linkByMaxError},
			},
		},
		{
			"validation success",
			mdSuccess,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := p.validateProposalMetadata(test.metadata)

			if err != nil {
				// Validate error code
				gotErrCode := err.(www.UserError).ErrorCode
				wantErrCode := test.wantError.(www.UserError).ErrorCode

				if gotErrCode != wantErrCode {
					t.Errorf("got error code %v, want %v",
						gotErrCode, wantErrCode)
				}
				// Validate error context
				gotErrContext := err.(www.UserError).ErrorContext
				wantErrContext := test.wantError.(www.UserError).ErrorContext
				hasContext := len(gotErrContext) > 0 && len(wantErrContext) > 0

				if hasContext && (gotErrContext[0] != wantErrContext[0]) {
					t.Errorf("got error context '%v', want '%v'",
						gotErrContext[0], wantErrContext[0])
				}

			}

		})
	}
}

func TestValidateProposal(t *testing.T) {
	// Setup politeiawww and a test user
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	usr, id := newUser(t, p, true, false)

	// Create test data
	md := createFileMD(t, 8)
	png := createFilePNG(t, false)
	np := createNewProposal(t, id, []www.File{*md, *png}, "")

	// Invalid signature
	propInvalidSig := createNewProposal(t, id, []www.File{*md}, "")
	propInvalidSig.Signature = "abc"

	// Signature is valid but incorrect
	propBadSig := createNewProposal(t, id, []www.File{*md}, "")
	propBadSig.Signature = np.Signature

	// No files
	propNoFiles := createNewProposal(t, id, []www.File{}, "")

	// Invalid markdown filename
	mdBadFilename := *md
	mdBadFilename.Name = "bad_filename.md"
	propBadFilename := createNewProposal(t, id, []www.File{mdBadFilename}, "")

	// Duplicate filenames
	propDupFiles := createNewProposal(t, id, []www.File{*md, *png, *png}, "")

	// Too many markdown files. We need one correctly named md
	// file and the rest must have their names changed so that we
	// don't get a duplicate filename error.
	files := make([]www.File, 0, www.PolicyMaxMDs+1)
	files = append(files, *md)
	for i := 0; i < www.PolicyMaxMDs; i++ {
		m := *md
		m.Name = fmt.Sprintf("%v.md", i)
		files = append(files, m)
	}
	propMaxMDFiles := createNewProposal(t, id, files, "")

	// Too many image files. All of their names must be different
	// so that we don't get a duplicate filename error.
	files = make([]www.File, 0, www.PolicyMaxImages+2)
	files = append(files, *md)
	for i := 0; i <= www.PolicyMaxImages; i++ {
		p := *png
		p.Name = fmt.Sprintf("%v.png", i)
		files = append(files, p)
	}
	propMaxImages := createNewProposal(t, id, files, "")

	// Markdown file too large
	mdLarge := createFileMD(t, www.PolicyMaxMDSize)
	propMDLarge := createNewProposal(t, id, []www.File{*mdLarge, *png}, "")

	// Image too large
	pngLarge := createFilePNG(t, true)
	propImageLarge := createNewProposal(t, id, []www.File{*md, *pngLarge}, "")

	// Invalid proposal title
	mdBadTitle := createFileMD(t, 8)
	propBadTitle := createNewProposal(t, id,
		[]www.File{*mdBadTitle}, "{invalid-title}")

	// Empty file payload
	propEmptyFile := createNewProposal(t, id, []www.File{*md}, "")
	emptyFile := createFileMD(t, 8)
	emptyFile.Payload = ""
	propEmptyFile.Files = []www.File{*emptyFile}

	// Invalid file digest
	propInvalidDigest := createNewProposal(t, id, []www.File{*md}, "")
	invalidDigestFile := createFilePNG(t, false)
	invalidDigestFile.Digest = ""
	propInvalidDigest.Files = append(propInvalidDigest.Files, *invalidDigestFile)

	// Invalid MIME type
	propInvalidMIME := createNewProposal(t, id, []www.File{*md}, "")
	invalidMIMEFile := createFilePNG(t, false)
	invalidMIMEFile.MIME = "image/jpeg"
	propInvalidMIME.Files = append(propInvalidMIME.Files, *invalidMIMEFile)

	// Invalid metadata
	propInvalidMetadata := createNewProposal(t, id, []www.File{*md}, "")
	invalidMd := www.Metadata{
		Digest:  "",
		Payload: "",
		Hint:    www.HintProposalMetadata,
	}
	propInvalidMetadata.Metadata = append(propInvalidMetadata.Metadata, invalidMd)

	// Missing metadata
	propMissingMetadata := createNewProposal(t, id, []www.File{*md}, "")
	propMissingMetadata.Metadata = nil

	// Setup test cases
	var tests = []struct {
		name        string
		newProposal www.NewProposal
		user        *user.User
		want        error
	}{
		{
			"correct proposal",
			*np,
			usr,
			nil,
		},
		{
			"invalid signature",
			*propInvalidSig,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			},
		},
		{
			"incorrect signature",
			*propBadSig,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			},
		},
		{
			"missing files",
			*propNoFiles,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusProposalMissingFiles,
			},
		},
		{
			"bad md filename",
			*propBadFilename,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxMDsExceededPolicy,
			},
		},
		{
			"duplicate filenames",
			*propDupFiles,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusProposalDuplicateFilenames,
			},
		},
		{
			"empty file payload",
			*propEmptyFile,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidBase64,
			},
		},
		{
			"invalid file digest",
			*propInvalidDigest,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidFileDigest,
			},
		},
		{
			"invalid file MIME type",
			*propInvalidMIME,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidMIMEType,
			},
		},
		{
			"invalid metadata",
			*propInvalidMetadata,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMetadataInvalid,
			},
		},
		{
			"missing metadata",
			*propMissingMetadata,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMetadataMissing,
			},
		},
		{
			"too may md files",
			*propMaxMDFiles,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxMDsExceededPolicy,
			},
		},
		{
			"too many images",
			*propMaxImages,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxImagesExceededPolicy,
			},
		},
		{
			"md file too large",
			*propMDLarge,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxMDSizeExceededPolicy,
			},
		},
		{
			"image too large",
			*propImageLarge,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxImageSizeExceededPolicy,
			},
		},
		{
			"invalid title",
			*propBadTitle,
			usr,
			www.UserError{
				ErrorCode: www.ErrorStatusProposalInvalidTitle,
			},
		},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := p.validateProposal(test.newProposal, test.user)
			got := errToStr(err)
			want := errToStr(test.want)
			if got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

func TestValidateAuthorizeVote(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	d := newTestPoliteiad(t, p)
	defer d.Close()

	usr, id := newUser(t, p, true, false)
	_, id2 := newUser(t, p, true, false)

	authorize := decredplugin.AuthVoteActionAuthorize
	revoke := decredplugin.AuthVoteActionRevoke

	// Public proposal
	prop := newProposalRecord(t, usr, id, www.PropStatusPublic)
	token := prop.CensorshipRecord.Token
	d.AddRecord(t, convertPropToPD(t, prop))

	// Authorize vote
	av := newAuthorizeVote(token, prop.Version, authorize, id)

	// Revoke vote
	rv := newAuthorizeVote(token, prop.Version, revoke, id)

	// Wrong status proposal
	propUnreviewed := newProposalRecord(t, usr, id, www.PropStatusNotReviewed)
	d.AddRecord(t, convertPropToPD(t, prop))

	// Invalid signing key
	avInvalid := newAuthorizeVote(token, prop.Version, authorize, id)
	avInvalid.PublicKey = hex.EncodeToString(id2.Public.Key[:])

	// Invalid vote action
	avInvalidAct := newAuthorizeVote(token, prop.Version, "bad", id)

	var tests = []struct {
		name string
		av   www.AuthorizeVote
		u    user.User
		pr   www.ProposalRecord
		vs   www.VoteSummary
		want error
	}{
		{
			"invalid signing key",
			avInvalid,
			*usr,
			prop,
			www.VoteSummary{},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSigningKey,
			},
		},
		{
			"wrong proposal status",
			av,
			*usr,
			propUnreviewed,
			www.VoteSummary{},
			www.UserError{
				ErrorCode: www.ErrorStatusWrongStatus,
			},
		},
		{
			"vote has already started",
			av,
			*usr,
			prop,
			www.VoteSummary{
				EndHeight: 1552,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusWrongVoteStatus,
			},
		},
		{
			"invalid auth vote action",
			avInvalidAct,
			*usr,
			prop,
			www.VoteSummary{},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidAuthVoteAction,
			},
		},
		{
			"vote has already been authorized",
			av,
			*usr,
			prop,
			www.VoteSummary{
				Status: www.PropVoteStatusAuthorized,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVoteAlreadyAuthorized,
			},
		},
		{
			"cannot revoke vote that has not been authorized",
			rv,
			*usr,
			prop,
			www.VoteSummary{
				Status: www.PropVoteStatusNotAuthorized,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVoteNotAuthorized,
			},
		},
		{
			"valid authorize vote",
			av,
			*usr,
			prop,
			www.VoteSummary{},
			nil,
		},
		{
			"valid revoke vote",
			rv,
			*usr,
			prop,
			www.VoteSummary{
				Status: www.PropVoteStatusAuthorized,
			},
			nil,
		},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAuthorizeVote(test.av, test.u, test.pr, test.vs)
			got := errToStr(err)
			want := errToStr(test.want)
			if got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

func TestValidateAuthorizeVoteStandard(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	d := newTestPoliteiad(t, p)
	defer d.Close()

	usr, id := newUser(t, p, true, false)
	_, id2 := newUser(t, p, true, false)

	authorize := decredplugin.AuthVoteActionAuthorize

	// RFP proposal
	rfpProp := newProposalRecord(t, usr, id, www.PropStatusPublic)
	rfpPropToken := rfpProp.CensorshipRecord.Token
	d.AddRecord(t, convertPropToPD(t, rfpProp))

	// RFP proposal submission
	prop := newProposalRecord(t, usr, id, www.PropStatusPublic)
	token := prop.CensorshipRecord.Token
	makeProposalRFPSubmissions(t, []*www.ProposalRecord{&prop}, rfpPropToken)
	d.AddRecord(t, convertPropToPD(t, prop))

	// Public proposal submission wrong author
	prop2 := newProposalRecord(t, usr, id, www.PropStatusPublic)
	prop2.PublicKey = hex.EncodeToString(id2.Public.Key[:])
	d.AddRecord(t, convertPropToPD(t, prop2))

	// Valid proposal vote auth
	propValid := newProposalRecord(t, usr, id, www.PropStatusPublic)
	d.AddRecord(t, convertPropToPD(t, propValid))

	// Authorize vote
	av := newAuthorizeVote(token, prop.Version, authorize, id)

	var tests = []struct {
		name string
		av   www.AuthorizeVote
		u    user.User
		pr   www.ProposalRecord
		vs   www.VoteSummary
		want error
	}{
		{
			"proposal is a RFP submission",
			av,
			*usr,
			prop,
			www.VoteSummary{},
			fmt.Errorf("proposal is a runoff vote submission"),
		},
		{
			"not proposal author",
			av,
			*usr,
			prop2,
			www.VoteSummary{},
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotAuthor,
			},
		},
		{
			"valid",
			av,
			*usr,
			propValid,
			www.VoteSummary{},
			nil,
		},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAuthorizeVoteStandard(test.av, test.u, test.pr, test.vs)
			got := errToStr(err)
			want := errToStr(test.want)
			if got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

func TestValidateAuthorizeVoteRunoff(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	d := newTestPoliteiad(t, p)
	defer d.Close()

	usr, id := newUser(t, p, true, true)
	usrNotAdmin, _ := newUser(t, p, true, false)

	authorize := decredplugin.AuthVoteActionAuthorize

	// Public proposal
	prop := newProposalRecord(t, usr, id, www.PropStatusPublic)
	token := prop.CensorshipRecord.Token
	d.AddRecord(t, convertPropToPD(t, prop))

	// Authorize vote
	av := newAuthorizeVote(token, prop.Version, authorize, id)

	var tests = []struct {
		name string
		av   www.AuthorizeVote
		u    user.User
		pr   www.ProposalRecord
		vs   www.VoteSummary
		want error
	}{
		{
			"user is not an admin",
			av,
			*usrNotAdmin,
			prop,
			www.VoteSummary{},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSigningKey,
			},
		},
		{
			"valid",
			av,
			*usr,
			prop,
			www.VoteSummary{},
			nil,
		},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAuthorizeVoteRunoff(test.av, test.u, test.pr, test.vs)
			got := errToStr(err)
			want := errToStr(test.want)
			if got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

func TestValidateVoteOptions(t *testing.T) {
	invalidVoteOption := []www2.VoteOption{
		{
			Id:          "wrong",
			Description: "",
			Bits:        0,
		},
	}
	missingReject := []www2.VoteOption{
		{
			Id:          decredplugin.VoteOptionIDApprove,
			Description: "",
			Bits:        0,
		},
	}
	missingApprove := []www2.VoteOption{
		{
			Id:          decredplugin.VoteOptionIDReject,
			Description: "",
			Bits:        1,
		},
	}
	valid := []www2.VoteOption{
		{
			Id:          decredplugin.VoteOptionIDApprove,
			Description: "approve",
			Bits:        0,
		},
		{
			Id:          decredplugin.VoteOptionIDReject,
			Description: "reject",
			Bits:        1,
		},
	}
	var tests = []struct {
		name string
		vos  []www2.VoteOption
		want error
	}{
		{
			"no vote options found",
			[]www2.VoteOption{},
			www.UserError{
				ErrorCode:    www.ErrorStatusInvalidVoteOptions,
				ErrorContext: []string{"no vote options found"},
			},
		},
		{
			"invalid vote option",
			invalidVoteOption,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidVoteOptions,
				ErrorContext: []string{
					fmt.Sprintf("invalid vote option id 'wrong'"),
				},
			},
		},
		{
			"missing reject vote option",
			missingReject,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidVoteOptions,
				ErrorContext: []string{
					fmt.Sprintf("missing vote option id 'no'"),
				},
			},
		},
		{
			"missing approve vote option",
			missingApprove,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidVoteOptions,
				ErrorContext: []string{
					fmt.Sprintf("missing vote option id 'yes'"),
				},
			},
		},
		{
			"valid",
			valid,
			nil,
		},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateVoteOptions(test.vos)

			if err != nil {
				// Validate error code
				gotErrCode := err.(www.UserError).ErrorCode
				wantErrCode := test.want.(www.UserError).ErrorCode

				if gotErrCode != wantErrCode {
					t.Errorf("got error code %v, want %v",
						gotErrCode, wantErrCode)
				}
				// Validate error context
				gotErrContext := err.(www.UserError).ErrorContext
				wantErrContext := test.want.(www.UserError).ErrorContext
				hasContext := len(gotErrContext) > 0 && len(wantErrContext) > 0

				if hasContext && (gotErrContext[0] != wantErrContext[0]) {
					t.Errorf("got error context '%v', want '%v'",
						gotErrContext[0], wantErrContext[0])
				}

			}
		})
	}
}

func TestFilterProposals(t *testing.T) {
	// Test proposal page size. Only a single page of proposals
	// should be returned.
	t.Run("proposal page size", func(t *testing.T) {
		pq := proposalsFilter{
			StateMap: map[www.PropStateT]bool{
				www.PropStateVetted: true,
			},
		}

		// We use simplified userIDs, timestamps, and censorship
		// record tokens. This is ok since filterProps() does not
		// check the validity of the data.
		c := www.ProposalListPageSize + 5
		propsPageTest := make([]www.ProposalRecord, 0, c)
		for i := 1; i <= c; i++ {
			propsPageTest = append(propsPageTest, www.ProposalRecord{
				State:     www.PropStateVetted,
				UserId:    strconv.Itoa(i),
				Timestamp: int64(i),
				CensorshipRecord: www.CensorshipRecord{
					Token: strconv.Itoa(i),
				},
			})
		}

		out := filterProps(pq, propsPageTest)
		if len(out) != www.ProposalListPageSize {
			t.Errorf("got %v, want %v", len(out), www.ProposalListPageSize)
		}
	})

	// Create data for test table. We use simplified userIDs,
	// timestamps, and censorship record tokens. This is ok since
	// filterProps() does not check the validity of the data.
	props := make(map[int]*www.ProposalRecord, 5)
	for i := 1; i <= 5; i++ {
		props[i] = &www.ProposalRecord{
			State:     www.PropStateVetted,
			UserId:    strconv.Itoa(i),
			Timestamp: int64(i),
			CensorshipRecord: www.CensorshipRecord{
				Token: strconv.Itoa(i),
			},
		}
	}

	// Change the State of a few proposals so that they are not
	// all the same.
	props[2].State = www.PropStateUnvetted
	props[4].State = www.PropStateUnvetted

	// Setup tests
	var tests = []struct {
		name  string
		req   proposalsFilter
		input []www.ProposalRecord
		want  []www.ProposalRecord
	}{
		{"filter by State",
			proposalsFilter{
				StateMap: map[www.PropStateT]bool{
					www.PropStateUnvetted: true,
				},
			},
			[]www.ProposalRecord{
				*props[1], *props[2], *props[3], *props[4], *props[5],
			},
			[]www.ProposalRecord{
				*props[4], *props[2],
			},
		},

		{"filter by UserID",
			proposalsFilter{
				UserID: "1",
				StateMap: map[www.PropStateT]bool{
					www.PropStateVetted: true,
				},
			},
			[]www.ProposalRecord{
				*props[1], *props[2], *props[3], *props[4], *props[5],
			},
			[]www.ProposalRecord{
				*props[1],
			},
		},

		{"filter by Before",
			proposalsFilter{
				Before: props[3].CensorshipRecord.Token,
				StateMap: map[www.PropStateT]bool{
					www.PropStateUnvetted: true,
					www.PropStateVetted:   true,
				},
			},
			[]www.ProposalRecord{
				*props[1], *props[2], *props[3], *props[4], *props[5],
			},
			[]www.ProposalRecord{
				*props[5], *props[4],
			},
		},

		{"filter by After",
			proposalsFilter{
				After: props[3].CensorshipRecord.Token,
				StateMap: map[www.PropStateT]bool{
					www.PropStateUnvetted: true,
					www.PropStateVetted:   true,
				},
			},
			[]www.ProposalRecord{
				*props[1], *props[2], *props[3], *props[4], *props[5],
			},
			[]www.ProposalRecord{
				*props[2], *props[1],
			},
		},

		{"unsorted proposals",
			proposalsFilter{
				StateMap: map[www.PropStateT]bool{
					www.PropStateUnvetted: true,
					www.PropStateVetted:   true,
				},
			},
			[]www.ProposalRecord{
				*props[3], *props[4], *props[1], *props[5], *props[2],
			},
			[]www.ProposalRecord{
				*props[5], *props[4], *props[3], *props[2], *props[1],
			},
		},
	}

	// Run tests
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := filterProps(test.req, test.input)

			// Pull out the tokens to make it easier to view the
			// difference between want and got
			want := make([]string, len(test.want))
			for _, p := range test.want {
				want = append(want, p.CensorshipRecord.Token)
			}
			got := make([]string, len(out))
			for _, p := range out {
				got = append(got, p.CensorshipRecord.Token)
			}

			// Check if want and got are the same
			if len(want) != len(got) {
				goto fail
			}
			for i, w := range want {
				if w != got[i] {
					goto fail
				}
			}

			// success; want and got are the same
			return

		fail:
			t.Errorf("got %v, want %v", got, want)
		})
	}
}

func TestProcessNewProposal(t *testing.T) {
	// Setup test environment
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	td := testpoliteiad.New(t, p.cache)
	defer td.Close()

	p.cfg.RPCHost = td.URL
	p.cfg.Identity = td.PublicIdentity

	// Create a user that has not paid their registration fee.
	usrUnpaid, _ := newUser(t, p, true, false)

	// Create a user that has paid their registration
	// fee but does not have any proposal credits.
	usrNoCredits, _ := newUser(t, p, true, false)
	payRegistrationFee(t, p, usrNoCredits)

	// Create a user that has paid their registration
	// fee and has purchased proposal credits.
	usrValid, id := newUser(t, p, true, false)
	payRegistrationFee(t, p, usrValid)
	addProposalCredits(t, p, usrValid, 10)

	// Create a NewProposal
	f := newFileRandomMD(t)
	np := createNewProposal(t, id, []www.File{f}, "")

	// Invalid proposal
	propInvalid := createNewProposal(t, id, []www.File{f}, "")
	propInvalid.Signature = ""

	// Setup tests
	var tests = []struct {
		name string
		np   *www.NewProposal
		usr  *user.User
		want error
	}{
		{"unpaid registration fee", np, usrUnpaid,
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotPaid,
			}},

		{"no proposal credits", np, usrNoCredits,
			www.UserError{
				ErrorCode: www.ErrorStatusNoProposalCredits,
			}},

		{"invalid proposal",
			propInvalid,
			usrValid,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			}},

		{"success", np, usrValid, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			npr, err := p.processNewProposal(*v.np, v.usr)
			got := errToStr(err)
			want := errToStr(v.want)

			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}

			if v.want != nil {
				// Test case passes
				return
			}

			// Validate success case
			if npr == nil {
				t.Errorf("NewProposalReply is nil")
			}

			// Ensure a proposal credit has been deducted
			// from the user's account.
			u, err := p.db.UserGetById(v.usr.ID)
			if err != nil {
				t.Error(err)
			}

			gotCredits := len(u.UnspentProposalCredits)
			wantCredits := len(v.usr.UnspentProposalCredits)
			if gotCredits != wantCredits {
				t.Errorf("got num proposal credits %v, want %v",
					gotCredits, wantCredits)
			}
		})
	}
}

func TestProcessEditProposal(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	d := newTestPoliteiad(t, p)
	defer d.Close()

	usr, id := newUser(t, p, true, false)
	notAuthorUser, _ := newUser(t, p, true, false)

	// Public proposal to be edited
	propPublic := newProposalRecord(t, usr, id, www.PropStatusPublic)
	tokenPropPublic := propPublic.CensorshipRecord.Token
	d.AddRecord(t, convertPropToPD(t, propPublic))

	root := merkleRoot(t, propPublic.Files, propPublic.Metadata)
	s := id.SignMessage([]byte(root))
	sigPropPublic := hex.EncodeToString(s[:])

	// Edited public proposal
	newMD := newFileRandomMD(t)
	png := createFilePNG(t, false)
	newFiles := []www.File{newMD, *png}

	root = merkleRoot(t, newFiles, propPublic.Metadata)
	s = id.SignMessage([]byte(root))
	sigPropPublicEdited := hex.EncodeToString(s[:])

	// Censored proposal to test error case
	propCensored := newProposalRecord(t, usr, id, www.PropStatusCensored)
	tokenPropCensored := propCensored.CensorshipRecord.Token
	d.AddRecord(t, convertPropToPD(t, propCensored))

	// Authorized vote proposal to test error case
	propVoteAuthorized := newProposalRecord(t, usr, id, www.PropStatusPublic)
	tokenVoteAuthorized := propVoteAuthorized.CensorshipRecord.Token
	d.AddRecord(t, convertPropToPD(t, propVoteAuthorized))

	cmd := newAuthorizeVoteCmd(t, tokenVoteAuthorized,
		propVoteAuthorized.Version, decredplugin.AuthVoteActionAuthorize, id)
	d.Plugin(t, cmd)

	var tests = []struct {
		name      string
		user      *user.User
		editProp  www.EditProposal
		wantError error
	}{
		{
			"invalid proposal token",
			usr,
			www.EditProposal{
				Token: "invalid-token",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidCensorshipToken,
			},
		},
		{
			"wrong proposal status",
			usr,
			www.EditProposal{
				Token: tokenPropCensored,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusWrongStatus,
			},
		},
		{
			"user is not the author",
			notAuthorUser,
			www.EditProposal{
				Token: tokenPropPublic,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotAuthor,
			},
		},
		{
			"wrong proposal vote status",
			usr,
			www.EditProposal{
				Token: tokenVoteAuthorized,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusWrongVoteStatus,
			},
		},
		{
			"no changes in proposal md file",
			usr,
			www.EditProposal{
				Token:     tokenPropPublic,
				Files:     propPublic.Files,
				Metadata:  propPublic.Metadata,
				PublicKey: usr.PublicKey(),
				Signature: sigPropPublic,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusNoProposalChanges,
			},
		},
		{
			"success",
			usr,
			www.EditProposal{
				Token:     tokenPropPublic,
				Files:     newFiles,
				Metadata:  propPublic.Metadata,
				PublicKey: usr.PublicKey(),
				Signature: sigPropPublicEdited,
			},
			nil,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processEditProposal(v.editProp, v.user)
			got := errToStr(err)
			want := errToStr(v.wantError)

			// Test if we got expected error
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
			}
		})
	}
}

func TestProcessSetProposalStatus(t *testing.T) {
	// Setup test environment
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	d := newTestPoliteiad(t, p)
	defer d.Close()

	// Create test data
	admin, id := newUser(t, p, true, true)

	changeMsgCensored := "proposal did not meet guidelines"
	changeMsgAbandoned := "no activity"

	statusPublic := strconv.Itoa(int(www.PropStatusPublic))
	statusCensored := strconv.Itoa(int(www.PropStatusCensored))
	statusAbandoned := strconv.Itoa(int(www.PropStatusAbandoned))

	propNotReviewed := newProposalRecord(t, admin, id, www.PropStatusNotReviewed)
	propPublic := newProposalRecord(t, admin, id, www.PropStatusPublic)

	tokenNotReviewed := propNotReviewed.CensorshipRecord.Token
	tokenPublic := propPublic.CensorshipRecord.Token
	tokenNotFound := "abc"

	msg := fmt.Sprintf("%s%s", tokenNotReviewed, statusPublic)
	s := id.SignMessage([]byte(msg))
	sigNotReviewedToPublic := hex.EncodeToString(s[:])

	msg = fmt.Sprintf("%s%s%s", tokenNotReviewed,
		statusCensored, changeMsgCensored)
	s = id.SignMessage([]byte(msg))
	sigNotReviewedToCensored := hex.EncodeToString(s[:])

	msg = fmt.Sprintf("%s%s%s", tokenPublic,
		statusAbandoned, changeMsgAbandoned)
	s = id.SignMessage([]byte(msg))
	sigPublicToAbandoned := hex.EncodeToString(s[:])

	msg = fmt.Sprintf("%s%s", tokenNotFound, statusPublic)
	s = id.SignMessage([]byte(msg))
	sigNotFound := hex.EncodeToString(s[:])

	msg = fmt.Sprintf("%s%s%s", tokenNotReviewed,
		statusAbandoned, changeMsgAbandoned)
	s = id.SignMessage([]byte(msg))
	sigNotReviewedToAbandoned := hex.EncodeToString(s[:])

	// Add success case proposals to politeiad
	d.AddRecord(t, convertPropToPD(t, propNotReviewed))
	d.AddRecord(t, convertPropToPD(t, propPublic))

	// Create a proposal whose vote has been authorized
	propVoteAuthorized := newProposalRecord(t, admin, id, www.PropStatusPublic)
	tokenVoteAuthorized := propVoteAuthorized.CensorshipRecord.Token

	msg = fmt.Sprintf("%s%s%s", tokenVoteAuthorized,
		statusAbandoned, changeMsgAbandoned)
	s = id.SignMessage([]byte(msg))
	sigVoteAuthorizedToAbandoned := hex.EncodeToString(s[:])

	d.AddRecord(t, convertPropToPD(t, propVoteAuthorized))
	cmd := newAuthorizeVoteCmd(t, tokenVoteAuthorized,
		propVoteAuthorized.Version, decredplugin.AuthVoteActionAuthorize, id)
	d.Plugin(t, cmd)

	// Create a proposal whose voting period has started
	propVoteStarted := newProposalRecord(t, admin, id, www.PropStatusPublic)
	tokenVoteStarted := propVoteStarted.CensorshipRecord.Token

	msg = fmt.Sprintf("%s%s%s", tokenVoteStarted,
		statusAbandoned, changeMsgAbandoned)
	s = id.SignMessage([]byte(msg))
	sigVoteStartedToAbandoned := hex.EncodeToString(s[:])

	d.AddRecord(t, convertPropToPD(t, propVoteStarted))
	cmd = newStartVoteCmd(t, tokenVoteStarted, 1, id)
	d.Plugin(t, cmd)

	// Ensure that admins are not allowed to change the status of
	// their own proposal on mainnet. This is run individually
	// because it requires flipping the testnet config setting.
	t.Run("admin is author", func(t *testing.T) {
		p.cfg.TestNet = false
		defer func() {
			p.cfg.TestNet = true
		}()

		sps := www.SetProposalStatus{
			Token:          tokenNotReviewed,
			ProposalStatus: www.PropStatusPublic,
			Signature:      sigNotReviewedToPublic,
			PublicKey:      admin.PublicKey(),
		}

		_, err := p.processSetProposalStatus(sps, admin)
		got := errToStr(err)
		want := www.ErrorStatus[www.ErrorStatusReviewerAdminEqualsAuthor]
		if got != want {
			t.Errorf("got error %v, want %v",
				got, want)
		}
	})

	// Setup tests
	var tests = []struct {
		name string
		usr  *user.User
		sps  www.SetProposalStatus
		want error
	}{
		// This is an admin route so it can be assumed that the
		// user has been validated and is an admin.

		{"no change message for censored", admin,
			www.SetProposalStatus{
				Token:          tokenNotReviewed,
				ProposalStatus: www.PropStatusCensored,
				Signature:      sigNotReviewedToCensored,
				PublicKey:      admin.PublicKey(),
			},
			www.UserError{
				ErrorCode: www.ErrorStatusChangeMessageCannotBeBlank,
			}},

		{"no change message for abandoned", admin,
			www.SetProposalStatus{
				Token:          tokenPublic,
				ProposalStatus: www.PropStatusAbandoned,
				Signature:      sigPublicToAbandoned,
				PublicKey:      admin.PublicKey(),
			},
			www.UserError{
				ErrorCode: www.ErrorStatusChangeMessageCannotBeBlank,
			}},

		{"invalid public key", admin,
			www.SetProposalStatus{
				Token:          tokenNotReviewed,
				ProposalStatus: www.PropStatusPublic,
				Signature:      sigNotReviewedToPublic,
				PublicKey:      "",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSigningKey,
			}},

		{"invalid signature", admin,
			www.SetProposalStatus{
				Token:          tokenNotReviewed,
				ProposalStatus: www.PropStatusPublic,
				Signature:      "",
				PublicKey:      admin.PublicKey(),
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			}},

		{"invalid proposal token", admin,
			www.SetProposalStatus{
				Token:          tokenNotFound,
				ProposalStatus: www.PropStatusPublic,
				Signature:      sigNotFound,
				PublicKey:      admin.PublicKey(),
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidCensorshipToken,
			}},

		{"invalid status change", admin,
			www.SetProposalStatus{
				Token:               tokenNotReviewed,
				ProposalStatus:      www.PropStatusAbandoned,
				StatusChangeMessage: changeMsgAbandoned,
				Signature:           sigNotReviewedToAbandoned,
				PublicKey:           admin.PublicKey(),
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropStatusTransition,
			}},

		{"unvetted success", admin,
			www.SetProposalStatus{
				Token:          tokenNotReviewed,
				ProposalStatus: www.PropStatusPublic,
				Signature:      sigNotReviewedToPublic,
				PublicKey:      admin.PublicKey(),
			}, nil},

		{"vote already authorized", admin,
			www.SetProposalStatus{
				Token:               tokenVoteAuthorized,
				ProposalStatus:      www.PropStatusAbandoned,
				StatusChangeMessage: changeMsgAbandoned,
				Signature:           sigVoteAuthorizedToAbandoned,
				PublicKey:           admin.PublicKey(),
			},
			www.UserError{
				ErrorCode: www.ErrorStatusWrongVoteStatus,
			}},

		{"vote already started", admin,
			www.SetProposalStatus{
				Token:               tokenVoteStarted,
				ProposalStatus:      www.PropStatusAbandoned,
				StatusChangeMessage: changeMsgAbandoned,
				Signature:           sigVoteStartedToAbandoned,
				PublicKey:           admin.PublicKey(),
			},
			www.UserError{
				ErrorCode: www.ErrorStatusWrongVoteStatus,
			}},

		{"vetted success", admin,
			www.SetProposalStatus{
				Token:               tokenPublic,
				ProposalStatus:      www.PropStatusAbandoned,
				StatusChangeMessage: changeMsgAbandoned,
				Signature:           sigPublicToAbandoned,
				PublicKey:           admin.PublicKey(),
			}, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			reply, err := p.processSetProposalStatus(v.sps, v.usr)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}

			if err != nil {
				// Test case passes
				return
			}

			// Validate updated proposal
			if reply.Proposal.Status != v.sps.ProposalStatus {
				t.Errorf("got proposal status %v, want %v",
					reply.Proposal.Status, v.sps.ProposalStatus)
			}
		})
	}
}

func TestProcessAllVetted(t *testing.T) {
	// Setup test environment
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	d := newTestPoliteiad(t, p)
	defer d.Close()

	// Create test data
	tokenValid := "3575a65bbc3616c939acf6edf801e1168485dc864efef910034268f695351b5d"
	tokenNotHex := "3575a65bbc3616c939acf6edf801e1168485dc864efef910034268f695351zzz"
	tokenShort := "3575a65bbc3616c939acf6edf801e1168485dc864efef910034268f695351b5"
	tokenLong := "3575a65bbc3616c939acf6edf801e1168485dc864efef910034268f695351b5dd"

	// Setup tests
	var tests = []struct {
		name string
		av   www.GetAllVetted
		want error
	}{
		{"before token not hex",
			www.GetAllVetted{
				Before: tokenNotHex,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidCensorshipToken,
			},
		},
		{"before token invalid length short",
			www.GetAllVetted{
				Before: tokenShort,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidCensorshipToken,
			},
		},
		{"before token invalid length long",
			www.GetAllVetted{
				Before: tokenLong,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidCensorshipToken,
			},
		},
		{"after token not hex",
			www.GetAllVetted{
				After: tokenNotHex,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidCensorshipToken,
			},
		},
		{"after token invalid length short",
			www.GetAllVetted{
				After: tokenShort,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidCensorshipToken,
			},
		},
		{"after token invalid length long",
			www.GetAllVetted{
				After: tokenLong,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidCensorshipToken,
			},
		},
		{"valid before token",
			www.GetAllVetted{
				Before: tokenValid,
			},
			nil,
		},
		{"valid after token",
			www.GetAllVetted{
				After: tokenValid,
			},
			nil,
		},

		// XXX only partial test coverage has been added to this route
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processAllVetted(v.av)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestProcessAuthorizeVote(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	d := newTestPoliteiad(t, p)
	defer d.Close()

	usr, id := newUser(t, p, true, false)

	authorize := decredplugin.AuthVoteActionAuthorize

	// Public proposal
	prop := newProposalRecord(t, usr, id, www.PropStatusPublic)
	token := prop.CensorshipRecord.Token
	d.AddRecord(t, convertPropToPD(t, prop))

	// Proposal not found
	propNF := newProposalRecord(t, usr, id, www.PropStatusPublic)
	tokenNF := propNF.CensorshipRecord.Token
	avNF := newAuthorizeVote(tokenNF, propNF.Version, authorize, id)

	// Authorize vote
	av := newAuthorizeVote(token, prop.Version, authorize, id)

	s := d.FullIdentity.SignMessage([]byte(av.Signature))
	wantReceipt := hex.EncodeToString(s[:])

	var tests = []struct {
		name      string
		user      *user.User
		av        www.AuthorizeVote
		wantReply *www.AuthorizeVoteReply
		wantErr   error
	}{
		{
			"proposal not found",
			usr,
			avNF,
			&www.AuthorizeVoteReply{},
			www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			},
		},
		{
			"success",
			usr,
			av,
			&www.AuthorizeVoteReply{
				Action:  authorize,
				Receipt: wantReceipt,
			},
			nil,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			reply, err := p.processAuthorizeVote(v.av, v.user)
			got := errToStr(err)
			want := errToStr(v.wantErr)

			// Test if we got expected error
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
			}

			// Test received reply
			if err == nil {
				if !reflect.DeepEqual(v.wantReply, reply) {
					t.Errorf("got reply %v, want %v", reply, v.wantReply)
				}
			}
		})
	}
}

func TestVerifyStatusChange(t *testing.T) {
	invalid := www.PropStatusInvalid
	notFound := www.PropStatusNotFound
	notReviewed := www.PropStatusNotReviewed
	censored := www.PropStatusCensored
	public := www.PropStatusPublic
	unreviewedChanges := www.PropStatusUnreviewedChanges
	abandoned := www.PropStatusAbandoned

	// Setup tests
	var tests = []struct {
		name      string
		current   www.PropStatusT
		next      www.PropStatusT
		wantError bool
	}{
		{"not reviewed to invalid", notReviewed, invalid, true},
		{"not reviewed to not found", notReviewed, notFound, true},
		{"not reviewed to censored", notReviewed, censored, false},
		{"not reviewed to public", notReviewed, public, false},
		{"not reviewed to unreviewed changes", notReviewed, unreviewedChanges,
			true},
		{"not reviewed to abandoned", notReviewed, abandoned, true},
		{"censored to invalid", censored, invalid, true},
		{"censored to not found", censored, notFound, true},
		{"censored to not reviewed", censored, notReviewed, true},
		{"censored to public", censored, public, true},
		{"censored to unreviewed changes", censored, unreviewedChanges, true},
		{"censored to abandoned", censored, abandoned, true},
		{"public to invalid", public, invalid, true},
		{"public to not found", public, notFound, true},
		{"public to not reviewed", public, notReviewed, true},
		{"public to censored", public, censored, true},
		{"public to unreviewed changes", public, unreviewedChanges, true},
		{"public to abandoned", public, abandoned, false},
		{"unreviewed changes to invalid", unreviewedChanges, invalid, true},
		{"unreviewed changes to not found", unreviewedChanges, notFound, true},
		{"unreviewed changes to not reviewed", unreviewedChanges, notReviewed,
			true},
		{"unreviewed changes to censored", unreviewedChanges, censored, false},
		{"unreviewed changes to public", unreviewedChanges, public, false},
		{"unreviewed changes to abandoned", unreviewedChanges, abandoned, true},
		{"abandoned to invalid", abandoned, invalid, true},
		{"abandoned to not found", abandoned, notFound, true},
		{"abandoned to not reviewed", abandoned, notReviewed, true},
		{"abandoned to censored", abandoned, censored, true},
		{"abandoned to public", abandoned, public, true},
		{"abandoned to unreviewed changes", abandoned, unreviewedChanges, true},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			err := verifyStatusChange(v.current, v.next)
			got := errToStr(err)
			if v.wantError {
				want := www.ErrorStatus[www.ErrorStatusInvalidPropStatusTransition]
				if got != want {
					t.Errorf("got error %v, want %v",
						got, want)
				}

				// Test case passes
				return
			}

			if err != nil {
				t.Errorf("got error %v, want nil",
					got)
			}
		})
	}
}
