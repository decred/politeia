package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	pd "github.com/decred/politeia/politeiad/api/v1"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/database/localdb"
	"github.com/decred/politeia/util"
)

const (
	// indexFile contains the file name of the index file
	indexFile = "index.md"

	// mdStream* indicate the metadata stream used for various types
	mdStreamGeneral  = 0 // General information for this proposal
	mdStreamComments = 1 // Comments
	mdStreamChanges  = 2 // Changes to record
)

type MDStreamChanges struct {
	AdminPubKey string           // Identity of the administrator
	NewStatus   pd.RecordStatusT // NewStatus
	Timestamp   int64            // Timestamp of the change
}

// politeiawww backend construct
type backend struct {
	sync.RWMutex // lock for inventory and comments

	db                 database.Database
	cfg                *config
	commentJournalDir  string
	commentJournalFile string

	// These properties are only used for testing.
	test                   bool
	verificationExpiryTime time.Duration

	// Following entries require locks
	comments  map[string]map[uint64]BackendComment // [token][parent]comment
	commentID uint64                               // current comment id

	// When inventory is set or modified inventoryVersion MUST be
	// incremented.  When inventory changes the caller MUST initialize the
	// comments map for the associated censorship token.
	inventory        []www.ProposalRecord // current inventory
	inventoryVersion uint                 // inventory version
}

// NewBackend creates a new backend context for use in www and tests.
func NewBackend(cfg *config) (*backend, error) {
	// Setup database.
	//localdb.UseLogger(localdbLog)
	db, err := localdb.New(cfg.DataDir)
	if err != nil {
		return nil, err
	}

	// Context
	b := &backend{
		db:       db,
		cfg:      cfg,
		comments: make(map[string]map[uint64]BackendComment),
		commentJournalDir: filepath.Join(cfg.DataDir,
			defaultCommentJournalDir),
		commentID: 1, // Replay will set this value
	}

	// Setup comments
	os.MkdirAll(b.commentJournalDir, 0744)
	err = b.replayCommentJournals()
	if err != nil {
		return nil, err
	}

	// Flush comments
	err = b.flushCommentJournals()
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (b *backend) getVerificationExpiryTime() time.Duration {
	if b.verificationExpiryTime != time.Duration(0) {
		return b.verificationExpiryTime
	}
	return time.Duration(www.VerificationExpiryHours) * time.Hour
}

func (b *backend) generateVerificationTokenAndExpiry() ([]byte, int64, error) {
	token, err := util.Random(www.VerificationTokenSize)
	if err != nil {
		return nil, 0, err
	}

	expiry := time.Now().Add(b.getVerificationExpiryTime()).Unix()

	return token, expiry, nil
}

// hashPassword hashes the given password string with the default bcrypt cost
// or the minimum cost if the test flag is set to speed up running tests.
func (b *backend) hashPassword(password string) ([]byte, error) {
	if b.test {
		return bcrypt.GenerateFromPassword([]byte(password),
			bcrypt.MinCost)
	}
	return bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
}

// makeRequest makes an http request to the method and route provided, serializing
// the provided object as the request body.
func (b *backend) makeRequest(method string, route string, v interface{}) ([]byte, error) {
	var requestBody []byte
	if v != nil {
		var err error
		requestBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := b.cfg.RPCHost + route

	c, err := util.NewClient(false, b.cfg.RPCCert)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(b.cfg.RPCUser, b.cfg.RPCPass)
	r, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		var pdErrorReply www.PDErrorReply
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&pdErrorReply); err != nil {
			return nil, err
		}

		return nil, www.PDError{
			HTTPCode:   r.StatusCode,
			ErrorReply: pdErrorReply,
		}
	}

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	return responseBody, nil
}

// remoteInventory fetches the entire inventory of proposals from politeiad.
func (b *backend) remoteInventory() (*pd.InventoryReply, error) {
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	inv := pd.Inventory{
		Challenge:     hex.EncodeToString(challenge),
		IncludeFiles:  false,
		VettedCount:   0,
		BranchesCount: 0,
	}

	responseBody, err := b.makeRequest(http.MethodPost, pd.InventoryRoute, inv)
	if err != nil {
		return nil, err
	}

	var ir pd.InventoryReply
	err = json.Unmarshal(responseBody, &ir)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal InventoryReply: %v",
			err)
	}

	err = util.VerifyChallenge(b.cfg.Identity, challenge, ir.Response)
	if err != nil {
		return nil, err
	}

	return &ir, nil
}

// loadInventory calls the politeaid RPC call to load the current inventory.
// Note that this function fakes out the inventory during test and therefore
// must be called WITHOUT the lock held.
func (b *backend) loadInventory() (*pd.InventoryReply, error) {
	if !b.test {
		return b.remoteInventory()
	}

	// Split the existing inventory into vetted and unvetted.
	vetted := make([]www.ProposalRecord, 0)
	unvetted := make([]www.ProposalRecord, 0)

	b.Lock()
	defer b.Unlock()
	for _, v := range b.inventory {
		if v.Status == www.PropStatusPublic {
			vetted = append(vetted, v)
		} else {
			unvetted = append(unvetted, v)
		}
	}

	return &pd.InventoryReply{
		Vetted:   convertPropsFromWWW(vetted),
		Branches: convertPropsFromWWW(unvetted),
	}, nil
}

// LoadInventory fetches the entire inventory of proposals from politeiad and
// caches it, sorted by most recent timestamp.
func (b *backend) LoadInventory() error {
	// This function is a little hard to read but we must make sure that
	// the inventory has not changed since we tried to load it.  We can't
	// lock it for the duration because the RPC call is potentially very
	// slow.
	b.Lock()
	if b.inventory != nil {
		b.Unlock()
		return nil
	}
	currentInventory := b.inventoryVersion
	b.Unlock()

	// get remote inventory
	for {
		// Fetch remote inventory.
		inv, err := b.loadInventory()
		if err != nil {
			return fmt.Errorf("LoadInventory: %v", err)
		}

		b.Lock()
		// Restart operation if inventory changed from underneath us.
		if currentInventory != b.inventoryVersion {
			currentInventory = b.inventoryVersion
			b.Unlock()
			log.Debugf("LoadInventory: restarting reload")
			continue
		}

		b.inventory = make([]www.ProposalRecord, 0,
			len(inv.Vetted)+len(inv.Branches))
		for _, vv := range append(inv.Vetted, inv.Branches...) {
			v := convertPropFromPD(vv)
			// Initialize comment map for this proposal.
			b.initComment(v.CensorshipRecord.Token)
			len := len(b.inventory)
			if len == 0 {
				b.inventory = append(b.inventory, v)
				continue
			}
			idx := sort.Search(len, func(i int) bool {
				return v.Timestamp < b.inventory[i].Timestamp
			})

			// Insert the proposal at idx.
			b.inventory = append(b.inventory[:idx],
				append([]www.ProposalRecord{v},
					b.inventory[idx:]...)...)
		}
		b.inventoryVersion++
		b.Unlock()

		log.Infof("Adding %v vetted, %v unvetted proposals to the cache",
			len(inv.Vetted), len(inv.Branches))

		break
	}

	return nil
}
