// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/gitbe"
	"github.com/decred/politeia/util"
	"github.com/gorilla/mux"
	"github.com/kennygrant/sanitize"
)

// politeia application context.
type politeia struct {
	backend    backend.Backend
	cfg        *config
	router     *mux.Router
	httpClient *http.Client
	identity   *identity.FullIdentity
}

// convertBackendStatus converts a backend PSRStatus to an API status.
func convertBackendStatus(status backend.PSRStatusT) v1.StatusT {
	s := v1.StatusInvalid
	switch status {
	case backend.PSRStatusInvalid:
		s = v1.StatusInvalid
	case backend.PSRStatusUnvetted:
		s = v1.StatusNotReviewed
	case backend.PSRStatusVetted:
		s = v1.StatusPublic
	case backend.PSRStatusCensored:
		s = v1.StatusCensored
	}
	return s
}

// convertFrontendStatus convert an API status to a backend PSRStatus.
func convertFrontendStatus(status v1.StatusT) backend.PSRStatusT {
	s := backend.PSRStatusInvalid
	switch status {
	case v1.StatusInvalid:
		s = backend.PSRStatusInvalid
	case v1.StatusNotReviewed:
		s = backend.PSRStatusUnvetted
	case v1.StatusPublic:
		s = backend.PSRStatusVetted
	case v1.StatusCensored:
		s = backend.PSRStatusCensored
	}
	return s
}

func (p *politeia) convertBackendProposal(bpr backend.ProposalRecord) v1.ProposalRecord {
	psr := bpr.ProposalStorageRecord

	// Calculate signature
	merkleToken := make([]byte, len(psr.Merkle)+len(psr.Token))
	copy(merkleToken, psr.Merkle[:])
	copy(merkleToken[len(psr.Merkle[:]):], psr.Token)
	signature := p.identity.SignMessage(merkleToken)

	// Convert record
	pr := v1.ProposalRecord{
		Status:    convertBackendStatus(psr.Status),
		Name:      psr.Name,
		Timestamp: psr.Timestamp,
		CensorshipRecord: v1.CensorshipRecord{
			Merkle:    hex.EncodeToString(psr.Merkle[:]),
			Token:     hex.EncodeToString(psr.Token),
			Signature: hex.EncodeToString(signature[:]),
		},
	}
	pr.Files = make([]v1.File, 0, len(bpr.Files))
	for _, v := range bpr.Files {
		pr.Files = append(pr.Files,
			v1.File{
				Name:    v.Name,
				MIME:    v.MIME,
				Digest:  v.Digest,
				Payload: v.Payload,
			})
	}

	return pr
}

func (p *politeia) getIdentity(w http.ResponseWriter, r *http.Request) {
	var t v1.Identity
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}
	defer r.Body.Close()

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid challenge")
		return
	}
	response := p.identity.SignMessage(challenge)

	reply := v1.IdentityReply{
		Name:     p.identity.Public.Name,
		Nick:     p.identity.Public.Nick,
		Identity: hex.EncodeToString(p.identity.Public.Identity[:]),
		Key:      hex.EncodeToString(p.identity.Public.Key[:]),
		Response: hex.EncodeToString(response[:]),
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) newProposal(w http.ResponseWriter, r *http.Request) {
	var t v1.New
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}
	defer r.Body.Close()

	// Sanitize name
	t.Name = sanitize.Name(t.Name)
	if len(t.Name) > 80 {
		log.Errorf("%v New proposal: invalid name", r.RemoteAddr)
		util.RespondWithError(w, http.StatusBadRequest,
			"Could not create proposal: invalid name")
		return
	}
	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		log.Errorf("%v New proposal: invalid challenge", r.RemoteAddr)
		util.RespondWithError(w, http.StatusBadRequest,
			"Could not create proposal: invalid challenge")
		return
	}

	log.Infof("New proposal submitted %v: %v", r.RemoteAddr, t.Name)

	// Convert to backend call
	files := make([]backend.File, 0, len(t.Files))
	for _, v := range t.Files {
		files = append(files, backend.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}
	psr, err := p.backend.New(t.Name, files)
	if err != nil {
		// Check for content error.
		if _, ok := err.(*backend.ContentVerificationError); ok {
			log.Errorf("%v New proposal content error: %v %v",
				r.RemoteAddr, t.Name, err)
			util.RespondWithError(w, http.StatusBadRequest,
				fmt.Sprintf("Could not create proposal, "+
					"invalid content: %v", err))
			return
		}

		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v New proposal error code %v: %v", r.RemoteAddr,
			errorCode, err)

		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not create a new proposal, contact "+
				"administrator and provide the following "+
				"error code: %v", errorCode))
		return
	}

	// Prepare reply.
	merkleToken := make([]byte, len(psr.Merkle)+len(psr.Token))
	copy(merkleToken, psr.Merkle[:])
	copy(merkleToken[len(psr.Merkle[:]):], psr.Token)
	signature := p.identity.SignMessage(merkleToken)

	response := p.identity.SignMessage(challenge)
	reply := v1.NewReply{
		Response: hex.EncodeToString(response[:]),
		CensorshipRecord: v1.CensorshipRecord{
			Merkle:    hex.EncodeToString(psr.Merkle[:]),
			Token:     hex.EncodeToString(psr.Token),
			Signature: hex.EncodeToString(signature[:]),
		},
	}

	log.Infof("New proposal accepted %v: token %v name \"%v\"", r.RemoteAddr,
		reply.CensorshipRecord.Token, t.Name)

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) getUnvetted(w http.ResponseWriter, r *http.Request) {
	var t v1.GetUnvetted
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}
	defer r.Body.Close()

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid challenge")
		return
	}
	response := p.identity.SignMessage(challenge)

	reply := v1.GetUnvettedReply{
		Response: hex.EncodeToString(response[:]),
	}

	// Validate token
	token, err := util.ConvertStringToken(t.Token)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	// Ask backend about the censorship token.
	bpr, err := p.backend.GetUnvetted(token)
	if err == backend.ErrProposalNotFound {
		reply.Proposal.Status = v1.StatusNotFound
		log.Errorf("Get unvetted proposal %v: token %v not found",
			r.RemoteAddr, t.Token)
	} else if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v Get unvetted proposal error code %v: %v",
			r.RemoteAddr, errorCode, err)

		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieve unvetted proposal, "+
				"contact administrator and provide the "+
				"following error code: %v", errorCode))
		return
	} else {
		reply.Proposal = p.convertBackendProposal(*bpr)

		// Double check proposal bits before sending them off
		err := v1.Verify(p.identity.Public,
			reply.Proposal.CensorshipRecord, reply.Proposal.Files)
		if err != nil {
			// Generic internal error.
			errorCode := time.Now().Unix()
			log.Errorf("%v Get unvetted proposal CORRUPTION "+
				"error code %v: %v", r.RemoteAddr, errorCode,
				err)

			util.RespondWithError(w, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve unvetted "+
					"proposal, contact administrator and "+
					"provide the following error code: %v",
					errorCode))
			return
		}

		log.Infof("Get unvetted proposal %v: token %v name \"%v\"",
			r.RemoteAddr,
			t.Token, reply.Proposal.Name)
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) getVetted(w http.ResponseWriter, r *http.Request) {
	var t v1.GetVetted
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}
	defer r.Body.Close()

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid challenge")
		return
	}
	response := p.identity.SignMessage(challenge)

	reply := v1.GetVettedReply{
		Response: hex.EncodeToString(response[:]),
	}

	// Validate token
	token, err := util.ConvertStringToken(t.Token)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	// Ask backend about the censorship token.
	bpr, err := p.backend.GetVetted(token)
	if err == backend.ErrProposalNotFound {
		reply.Proposal.Status = v1.StatusNotFound
		log.Errorf("Get vetted proposal %v: token %v not found",
			r.RemoteAddr, t.Token)
	} else if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v Get vetted proposal error code %v: %v",
			r.RemoteAddr, errorCode, err)

		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieve vetted proposal, "+
				"contact administrator and provide the "+
				"following error code: %v", errorCode))
		return
	} else {
		reply.Proposal = p.convertBackendProposal(*bpr)

		// Double check proposal bits before sending them off
		err := v1.Verify(p.identity.Public,
			reply.Proposal.CensorshipRecord, reply.Proposal.Files)
		if err != nil {
			// Generic internal error.
			errorCode := time.Now().Unix()
			log.Errorf("%v Get vetted proposal CORRUPTION "+
				"error code %v: %v", r.RemoteAddr, errorCode,
				err)

			util.RespondWithError(w, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve vetted "+
					"proposal, contact administrator and "+
					"provide the following error code: %v",
					errorCode))
			return
		}
		log.Infof("Get vetted proposal %v: token %v name \"%v\"",
			r.RemoteAddr, t.Token, reply.Proposal.Name)
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) inventory(w http.ResponseWriter, r *http.Request) {
	var i v1.Inventory
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&i); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}
	defer r.Body.Close()

	challenge, err := hex.DecodeString(i.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid challenge")
		return
	}
	response := p.identity.SignMessage(challenge)

	reply := v1.InventoryReply{
		Response: hex.EncodeToString(response[:]),
	}

	// Ask backend for inventory
	prs, brs, err := p.backend.Inventory(i.VettedCount, i.BranchesCount,
		i.IncludeFiles)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v Inventory error code %v: %v", r.RemoteAddr,
			errorCode, err)

		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not inventory, contact "+
				"administrator and provide the following "+
				"error code: %v", errorCode))
		return
	}

	// Convert backend proposals
	vetted := make([]v1.ProposalRecord, 0, len(prs))
	for _, v := range prs {
		vetted = append(vetted, p.convertBackendProposal(v))
	}
	reply.Vetted = vetted

	// Convert branches
	_ = brs

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func checkAuth(w http.ResponseWriter, r *http.Request) bool {
	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		return false
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return false
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return false
	}

	return pair[0] == "user" && pair[1] == "pass"
}

func (p *politeia) check(user, pass string) bool {
	if user != p.cfg.RPCUser || pass != p.cfg.RPCPass {
		return false
	}
	return true
}

func (p *politeia) auth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !p.check(user, pass) {
			log.Errorf("%v Unauthorized access for: %v",
				r.RemoteAddr, user)
			w.Header().Set("WWW-Authenticate",
				`Basic realm="Politeiad"`)
			w.WriteHeader(401)
			w.Write([]byte("401 Unauthorized\n"))
			return
		}
		log.Infof("%v Authorized access for: %v",
			r.RemoteAddr, user)
		fn(w, r)
	}
}

func (p *politeia) setUnvettedStatus(w http.ResponseWriter, r *http.Request) {
	var t v1.SetUnvettedStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}
	defer r.Body.Close()

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid challenge")
		return
	}
	response := p.identity.SignMessage(challenge)

	// Validate token
	token, err := util.ConvertStringToken(t.Token)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	// Ask backend to update unvetted status
	status, err := p.backend.SetUnvettedStatus(token,
		convertFrontendStatus(t.Status))
	if err != nil {
		oldStatus := v1.Status[convertBackendStatus(status)]
		newStatus := v1.Status[t.Status]
		// Check for specific errors
		if err == backend.ErrInvalidTransition {
			log.Errorf("%v Invalid status code transition: "+
				"%v %v->%v", r.RemoteAddr, t.Token, oldStatus,
				newStatus)
			util.RespondWithError(w, http.StatusBadRequest,
				fmt.Sprintf("Invalid status code transition: "+
					"%v->%v", oldStatus, newStatus))
			return
		}
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v Set unvetted status error code %v: %v",
			r.RemoteAddr, errorCode, err)

		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not set unvetted status "+
				"contact administrator and provide the "+
				"following error code: %v", errorCode))
		return
	}
	reply := v1.SetUnvettedStatusReply{
		Response: hex.EncodeToString(response[:]),
		Status:   convertBackendStatus(status),
	}

	log.Infof("Set unvetted proposal status %v: token %v status %v",
		r.RemoteAddr, t.Token, v1.Status[reply.Status])

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// getError returns the error that is embedded in a JSON reply.
func getError(r io.Reader) (string, error) {
	var e interface{}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&e); err != nil {
		return "", err
	}
	m, ok := e.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Could not decode response")
	}
	rError, ok := m["error"]
	if !ok {
		return "", fmt.Errorf("No error response")
	}
	return fmt.Sprintf("%v", rError), nil
}

func logging(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Trace incoming request
		log.Tracef("%v", newLogClosure(func() string {
			trace, err := httputil.DumpRequest(r, true)
			if err != nil {
				trace = []byte(fmt.Sprintf("logging: "+
					"DumpRequest %v", err))
			}
			return string(trace)
		}))

		// Log incoming connection
		log.Infof("%v %v%v %v", r.Method, r.RemoteAddr, r.URL, r.Proto)
		f(w, r)
	}
}

func _main() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	loadedCfg, _, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	log.Infof("Version : %v", version())
	log.Infof("Network : %v", activeNetParams.Params.Name)
	log.Infof("Home dir: %v", loadedCfg.HomeDir)

	// Create the data directory in case it does not exist.
	err = os.MkdirAll(loadedCfg.DataDir, 0700)
	if err != nil {
		return err
	}

	// Generate the TLS cert and key file if both don't already
	// exist.
	if !fileExists(loadedCfg.HTTPSKey) &&
		!fileExists(loadedCfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P521(), "politeiad",
			loadedCfg.HTTPSCert, loadedCfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created...")
	}

	// Generate ed25519 identity to save messages, tokens etc.
	if !fileExists(loadedCfg.Identity) {
		log.Infof("Generating signing identity...")
		id, err := identity.New(util.FQDN(), "politeiad")
		if err != nil {
			return err
		}
		err = id.Save(loadedCfg.Identity)
		if err != nil {
			return err
		}
		log.Infof("Signing identity created...")
	}

	// Setup application context.
	p := &politeia{
		cfg: loadedCfg,
	}

	// Load identity.
	p.identity, err = identity.LoadFullIdentity(loadedCfg.Identity)
	if err != nil {
		return err
	}
	log.Infof("Public identity: %x", p.identity.Public.Identity)

	// Load certs, if there.  If they aren't there assume OS is used to
	// resolve cert validity.
	if len(loadedCfg.DcrtimeCert) != 0 {
		var certPool *x509.CertPool
		if !fileExists(loadedCfg.DcrtimeCert) {
			return fmt.Errorf("unable to find dcrtime cert %v",
				loadedCfg.DcrtimeCert)
		}
		dcrtimeCert, err := ioutil.ReadFile(loadedCfg.DcrtimeCert)
		if err != nil {
			return fmt.Errorf("unable to read dcrtime cert %v: %v",
				loadedCfg.DcrtimeCert, err)
		}
		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(dcrtimeCert) {
			return fmt.Errorf("unable to load cert")
		}
	}

	// Setup backend.
	gitbe.UseLogger(gitbeLog)
	b, err := gitbe.New(loadedCfg.DataDir, loadedCfg.DcrtimeHost, "",
		loadedCfg.GitTrace)
	if err != nil {
		return err
	}
	p.backend = b

	// Setup mux
	p.router = mux.NewRouter()

	// Unprivileged routes
	p.router.HandleFunc(v1.IdentityRoute,
		logging(p.getIdentity)).Methods("POST")
	p.router.HandleFunc(v1.NewRoute,
		logging(p.newProposal)).Methods("POST")
	p.router.HandleFunc(v1.GetUnvettedRoute,
		logging(p.getUnvetted)).Methods("POST")
	p.router.HandleFunc(v1.GetVettedRoute,
		logging(p.getVetted)).Methods("POST")

	// Routes that require auth
	p.router.HandleFunc(v1.InventoryRoute,
		logging(p.auth(p.inventory))).Methods("POST")
	p.router.HandleFunc(v1.SetUnvettedStatusRoute,
		logging(p.auth(p.setUnvettedStatus))).Methods("POST")

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range loadedCfg.Listeners {
		listen := listener
		go func() {
			log.Infof("Listen: %v", listen)
			listenC <- http.ListenAndServeTLS(listen,
				loadedCfg.HTTPSCert, loadedCfg.HTTPSKey,
				p.router)
		}()
	}

	// Tell user we are ready to go.
	log.Infof("Start of day")

	// Setup OS signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGINT)
	for {
		select {
		case sig := <-sigs:
			log.Infof("Terminating with %v", sig)
			goto done
		case err := <-listenC:
			log.Errorf("%v", err)
			goto done
		}
	}
done:
	p.backend.Close()

	log.Infof("Exiting")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
