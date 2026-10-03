package web

import (
	"io"
	"net/http"
	"strconv"

	"fleetwatch/internal/hub/logbuf"
)

type logsData struct {
	chrome
	Lines []logbuf.Line
	Start int64 // when the Hub started, Unix seconds
	Keeps int   // how many lines the buffer holds at most
}

// logsPage shows the Hub's own log. An htmx request with "after" gets the
// lines written after that sequence number, for a stream that reconnected.
func (w *Web) logsPage(rw http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") != "" {
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		w.render(rw, http.StatusOK, "loglines", w.logs.After(after))
		return
	}
	rows, err := w.rows(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "logs", logsData{chrome: w.chrome(r, "logs", rows), Lines: w.logs.Lines(),
		Start: w.logs.Start().Unix(), Keeps: w.logs.Size()})
}

func (w *Web) logsText(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.Header().Set("Content-Disposition", `attachment; filename="fleetwatch-hub.log"`)
	io.WriteString(rw, w.logs.Text())
}
