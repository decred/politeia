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
		session, err := p.store.Get(r, v1.CookieSession)
		if err != nil {
			log.Errorf("isLoggedIn: %v", err)
			util.RespondWithJSON(w, http.StatusForbidden, v1.ErrorReply{})
			return
		}

		// Check if user is authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
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
		session, err := p.store.Get(r, v1.CookieSession)
		if err != nil {
			log.Errorf("isLoggedInAsAdmin: %v", err)
			util.RespondWithJSON(w, http.StatusForbidden, v1.ErrorReply{})
			return
		}

		// Check if user is authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			util.RespondWithJSON(w, http.StatusForbidden, v1.ErrorReply{})
			return
		}

		// Check if user is an admin
		if admin, ok := session.Values["admin"].(bool); !ok || !admin {
			util.RespondWithJSON(w, http.StatusForbidden, v1.ErrorReply{})
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
