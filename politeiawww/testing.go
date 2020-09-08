// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/cache/testcache"
	"github.com/decred/politeia/politeiad/testpoliteiad"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	www2 "github.com/decred/politeia/politeiawww/api/www/v2"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/politeiawww/user/localdb"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// errToStr returns the string representation of the error. If the error is a
// UserError then the human readable error message is returned instead of the
// error code.
func errToStr(e error) string {
	if e == nil {
		return "nil"
	}

	userErr, ok := e.(www.UserError)
	if ok {
		return www.ErrorStatus[userErr.ErrorCode]
	}

	return e.Error()
}

func payRegistrationFee(t *testing.T, p *politeiawww, u *user.User) {
	t.Helper()

	u.NewUserPaywallAmount = 0
	u.NewUserPaywallTx = "cleared_during_testing"
	u.NewUserPaywallPollExpiry = 0

	err := p.db.UserUpdate(*u)
	if err != nil {
		t.Fatal(err)
	}
}

func addProposalCredits(t *testing.T, p *politeiawww, u *user.User, quantity int) {
	t.Helper()

	c := make([]user.ProposalCredit, quantity)
	ts := time.Now().Unix()
	for i := 0; i < quantity; i++ {
		c[i] = user.ProposalCredit{
			PaywallID:     0,
			Price:         0,
			DatePurchased: ts,
			TxID:          "created_during_testing",
		}
	}
	u.UnspentProposalCredits = append(u.UnspentProposalCredits, c...)

	err := p.db.UserUpdate(*u)
	if err != nil {
		t.Fatal(err)
	}
}

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

// newUser creates a new user using randomly generated user credentials and
// inserts the user into the database.  The user details and the full user
// identity are returned.
func newUser(t *testing.T, p *politeiawww, isVerified, isAdmin bool) (*user.User, *identity.FullIdentity) {
	t.Helper()

	// Generate random bytes to be used as user credentials
	r, err := util.Random(int(www.PolicyMinPasswordLength))
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Setup user
	pass, err := p.hashPassword(hex.EncodeToString(r))
	if err != nil {
		t.Fatalf("%v", err)
	}
	tokenb, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	u := user.User{
		ID:                        uuid.New(),
		Admin:                     isAdmin,
		Email:                     hex.EncodeToString(r) + "@example.com",
		Username:                  hex.EncodeToString(r),
		HashedPassword:            pass,
		NewUserVerificationToken:  tokenb,
		NewUserVerificationExpiry: expiry,
	}
	fid, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}
	pubkey := hex.EncodeToString(fid.Public.Key[:])
	id, err := user.NewIdentity(pubkey)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = u.AddIdentity(*id)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if isVerified {
		u.NewUserVerificationToken = nil
		u.NewUserVerificationExpiry = 0
		err := u.ActivateIdentity(id.Key[:])
		if err != nil {
			t.Fatalf("%v", err)
		}
	}

	// Add user to database
	err = p.db.UserNew(u)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Add the user to the politeiawww in-memory [email]userID
	// cache. Since the userID is generated in the database layer
	// we need to lookup the user in order to get the userID.
	usr, err := p.db.UserGetByUsername(u.Username)
	if err != nil {
		t.Fatalf("%v", err)
	}
	p.setUserEmailsCache(usr.Email, usr.ID)

	// Add paywall info to the user record
	err = p.GenerateNewUserPaywall(usr)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Lookup user record one more time so that
	// we return a user object with the paywall
	// details filled in.
	usr, err = p.db.UserGetByUsername(u.Username)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return usr, fid
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

func newStartVote(t *testing.T, token string, v uint32, d uint32, vt www2.VoteT, id *identity.FullIdentity) www2.StartVote {
	t.Helper()

	vote := www2.Vote{
		Token:            token,
		ProposalVersion:  v,
		Type:             vt,
		Mask:             0x03, // bit 0 no, bit 1 yes
		Duration:         d,
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

func newStartVoteCmd(t *testing.T, token string, proposalVersion uint32, d uint32, id *identity.FullIdentity) pd.PluginCommand {
	t.Helper()

	sv := newStartVote(t, token, proposalVersion, d, www2.VoteTypeStandard, id)
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

func newStartVoteRunoff(t *testing.T, tk string, avs []www2.AuthorizeVote, svs []www2.StartVote) www2.StartVoteRunoff {
	t.Helper()

	return www2.StartVoteRunoff{
		Token:          tk,
		AuthorizeVotes: avs,
		StartVotes:     svs,
	}
}

func newAuthorizeVoteV2(t *testing.T, token, version, action string, id *identity.FullIdentity) www2.AuthorizeVote {
	t.Helper()

	sig := id.SignMessage([]byte(token + version + action))
	return www2.AuthorizeVote{
		Token:     token,
		Action:    action,
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}
}

func newAuthorizeVote(t *testing.T, token, version, action string, id *identity.FullIdentity) www.AuthorizeVote {
	t.Helper()

	sig := id.SignMessage([]byte(token + version + action))
	return www.AuthorizeVote{
		Action:    action,
		Token:     token,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}
}

func newAuthorizeVoteCmd(t *testing.T, token, version, action string, id *identity.FullIdentity) pd.PluginCommand {
	t.Helper()

	av := newAuthorizeVote(t, token, version, action, id)
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
	t.Helper()

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

func newVoteOptionV2(t *testing.T, id, desc string, bits uint64) www2.VoteOption {
	t.Helper()

	return www2.VoteOption{
		Id:          id,
		Description: desc,
		Bits:        bits,
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

// newTestPoliteiawww returns a new politeiawww context that is setup for
// testing and a closure that cleans up the test environment when invoked.
func newTestPoliteiawww(t *testing.T) (*politeiawww, func()) {
	t.Helper()

	// Make a temp directory for test data. Temp directory
	// is removed in the returned closure.
	dataDir, err := ioutil.TempDir("", "politeiawww.test")
	if err != nil {
		t.Fatalf("open tmp dir: %v", err)
	}

	// Setup config
	cfg := &config{
		DataDir:         dataDir,
		PaywallAmount:   1e7,
		PaywallXpub:     "tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFmuMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx",
		TestNet:         true,
		VoteDurationMin: 2016,
		VoteDurationMax: 4032,
	}

	// Setup database
	db, err := localdb.New(filepath.Join(cfg.DataDir, "localdb"))
	if err != nil {
		t.Fatalf("setup database: %v", err)
	}

	// Setup smtp
	smtp, err := newSMTP("", "", "", "", nil, false)
	if err != nil {
		t.Fatalf("setup SMTP: %v", err)
	}

	// Setup sessions
	cookieKey, err := util.Random(32)
	if err != nil {
		t.Fatalf("create cookie key: %v", err)
	}

	// Setup logging
	initLogRotator(filepath.Join(dataDir, "politeiawww.test.log"))
	setLogLevels("off")

	// Create politeiawww context
	p := politeiawww{
		cfg:             cfg,
		db:              db,
		cache:           testcache.New(),
		params:          &chaincfg.TestNet3Params,
		router:          mux.NewRouter(),
		sessions:        NewSessionStore(db, sessionMaxAge, cookieKey),
		smtp:            smtp,
		test:            true,
		userEmails:      make(map[string]uuid.UUID),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
		commentVotes:    make(map[string]counters),
		voteSummaries:   make(map[string]www.VoteSummary),
	}

	// Setup routes
	p.setPoliteiaWWWRoutes()
	p.setUserWWWRoutes()

	// The cleanup is handled using a closure so that the temp dir
	// can be deleted using the local variable and not cfg.DataDir.
	// Using cfg.DataDir could be misused and lead to the deletion
	// of an unintended directory.
	return &p, func() {
		t.Helper()

		err := db.Close()
		if err != nil {
			t.Fatalf("close db: %v", err)
		}

		err = logRotator.Close()
		if err != nil {
			t.Fatalf("close log rotator: %v", err)
		}

		err = os.RemoveAll(dataDir)
		if err != nil {
			t.Fatalf("remove tmp dir: %v", err)
		}
	}
}

// newTestPoliteiad returns a new TestPoliteiad context. The relevant
// politeiawww config params are updated with the TestPoliteiad info.
func newTestPoliteiad(t *testing.T, p *politeiawww) *testpoliteiad.TestPoliteiad {
	td := testpoliteiad.New(t, p.cache)
	p.cfg.RPCHost = td.URL
	p.cfg.Identity = td.PublicIdentity
	return td
}

// newTestCMSwww returns a new cmswww context that is setup for
// testing and a closure that cleans up the test environment when invoked.
func newTestCMSwww(t *testing.T) (*politeiawww, func()) {
	t.Helper()

	// Make a temp directory for test data. Temp directory
	// is removed in the returned closure.
	dataDir, err := ioutil.TempDir("", "cmswww.test")
	if err != nil {
		t.Fatalf("open tmp dir: %v", err)
	}

	// Setup config
	cfg := &config{
		DataDir:         dataDir,
		PaywallAmount:   1e7,
		PaywallXpub:     "tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFmuMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx",
		TestNet:         true,
		VoteDurationMin: 2016,
		VoteDurationMax: 4032,
		Mode:            cmsWWWMode,
	}

	// Setup database
	db, err := localdb.New(filepath.Join(cfg.DataDir, "localdb"))
	if err != nil {
		t.Fatalf("setup database: %v", err)
	}

	// Register cms userdb plugin
	plugin := user.Plugin{
		ID:      user.CMSPluginID,
		Version: user.CMSPluginVersion,
	}
	err = db.RegisterPlugin(plugin)
	if err != nil {
		t.Fatalf("register userdb plugin: %v", err)
	}

	// Setup smtp
	smtp, err := newSMTP("", "", "", "", nil, false)
	if err != nil {
		t.Fatalf("setup SMTP: %v", err)
	}

	// Setup sessions
	cookieKey, err := util.Random(32)
	if err != nil {
		t.Fatalf("create cookie key: %v", err)
	}

	// Setup logging
	initLogRotator(filepath.Join(dataDir, "cmswww.test.log"))
	setLogLevels("off")

	// Create politeiawww context
	p := politeiawww{
		cfg:             cfg,
		db:              db,
		cache:           testcache.New(),
		params:          &chaincfg.TestNet3Params,
		router:          mux.NewRouter(),
		sessions:        NewSessionStore(db, sessionMaxAge, cookieKey),
		smtp:            smtp,
		test:            true,
		userEmails:      make(map[string]uuid.UUID),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
		commentVotes:    make(map[string]counters),
		voteSummaries:   make(map[string]www.VoteSummary),
	}

	// Setup routes
	p.setCMSWWWRoutes()
	p.setCMSUserWWWRoutes()

	// The cleanup is handled using a closure so that the temp dir
	// can be deleted using the local variable and not cfg.DataDir.
	// Using cfg.DataDir could be misused and lead to the deletion
	// of an unintended directory.
	return &p, func() {
		t.Helper()

		err := db.Close()
		if err != nil {
			t.Fatalf("close db: %v", err)
		}

		err = logRotator.Close()
		if err != nil {
			t.Fatalf("close log rotator: %v", err)
		}

		err = os.RemoveAll(dataDir)
		if err != nil {
			t.Fatalf("remove tmp dir: %v", err)
		}
	}
}
