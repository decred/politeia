package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

type User struct {
	Id int
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	// Authenticate the request, get the id from the route params,
	// and fetch the user from the DB, etc.

	// Get the token and pass it in the CSRF header. Our JSON-speaking client
	// or JavaScript framework can now read the header and return the token in
	// in its own "X-CSRF-Token" request header on the subsequent POST.
	fmt.Printf("token: %v\n", csrf.Token(r))
	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	//w.Header().Set("Token", csrf.Token(r))
	user := User{Id: 10}
	b, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write(b)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", GetUser)
	fmt.Printf("listening:\n")
	//http.ListenAndServe(":8000", r)
	http.ListenAndServe(":8000", csrf.Protect([]byte("32-byte-long-auth-key"),
		csrf.HttpOnly(false), csrf.Secure(false))(r))
}
