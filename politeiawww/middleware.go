package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

// isLoggedIn ensures that a user is logged in before calling the next
// function.
func (p *politeiawww) isLoggedIn(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("isLoggedIn: %v %v %v %v", remoteAddr(r), r.Method,
			r.URL, r.Proto)

		email, err := p.getSessionEmail(r)
		if err != nil {
			RespondWithError(w, r, 0,
				"isLoggedIn: getSessionEmail %v", err)
			return
		}

		// Check if user is authenticated
		if email == "" {
			util.RespondWithJSON(w, http.StatusForbidden, v1.ErrorReply{})
			return
		}

		f(w, r)
	}
}

// isLoggedInAsAdmin ensures that a user is logged in as an admin user
// before calling the next function.
func (p *politeiawww) isLoggedInAsAdmin(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("isLoggedInAsAdmin: %v %v %v %v", remoteAddr(r),
			r.Method, r.URL, r.Proto)

		// Check if user is admin
		isAdmin, err := p.isAdmin(r)
		if err != nil {
			log.Errorf("isLoggedInAsAdmin: isAdmin %v", err)
			util.RespondWithJSON(w, http.StatusForbidden, v1.ErrorReply{})
			return
		}
		if !isAdmin {
			return
		}

		f(w, r)
	}
}

// logging logs all incoming commands before calling the next funxtion.
//
// NOTE: LOGGING WILL LOG PASSWORDS IF TRACING IS ENABLED.
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
		log.Infof("%v %v %v %v", remoteAddr(r), r.Method, r.URL, r.Proto)
		f(w, r)
	}
}

func remoteAddr(r *http.Request) string {
	via := r.RemoteAddr
	xff := r.Header.Get(v1.Forward)
	if xff != "" {
		return fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	return via
}

func (p *politeiawww) loadInventory(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := p.backend.LoadInventory(); err != nil {
			RespondWithError(w, r, 0,
				"failed to get Load Inventory", err)
			return
		}
		f(w, r)
	}
}
