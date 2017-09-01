package main

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/davecgh/go-spew/spew"
)

func main() {
	client := &http.Client{}

	buf := []byte(`"id": "100"`)
	r := bytes.NewReader(buf)

	req, err := http.NewRequest("GET", "http://127.0.0.1:8000", r)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	csrfToken := resp.Header.Get("X-Csrf-Token")

	// lift csrf cookie
	r2 := bytes.NewReader(buf)
	req2, err := http.NewRequest("POST", "http://127.0.0.1:8000", r2)
	fmt.Printf("setting token: %v\n", csrfToken)
	req2.Header.Add("X-CSRF-Token", csrfToken)
	for _, cookie := range resp.Cookies() {
		fmt.Printf("setting cookie: %v %v\n", cookie.Name, cookie.Value)
		req2.AddCookie(cookie)
	}
	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	spew.Dump(resp2.Status)
}
