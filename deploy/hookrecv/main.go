// Command hookrecv is a stand-in webhook target for the end-to-end check. It
// prints every request it receives and answers 204.
package main

import (
	"io"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		log.Printf("%s %s %s", r.Method, r.URL.Path, body)
		w.WriteHeader(http.StatusNoContent)
	})
	log.Print("hookrecv listening on :9000")
	log.Fatal(http.ListenAndServe(":9000", nil))
}
