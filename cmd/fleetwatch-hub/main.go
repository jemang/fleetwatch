// Command fleetwatch-hub serves the agent API and the dashboard.
package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	_ "time/tzdata" // the image has no zoneinfo; TZ needs it

	"fleetwatch/internal/hub/alert"
	"fleetwatch/internal/hub/api"
	"fleetwatch/internal/hub/dist"
	"fleetwatch/internal/hub/limit"
	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/logbuf"
	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/hub/web"
	"fleetwatch/internal/release/pubkey"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("fleetwatch-hub: %v", err)
	}
}

// slowRequest is the duration from which a request is worth a log line.
const slowRequest = time.Second

// keptLogLines is how many of the Hub's own log lines the Logs page can show.
const keptLogLines = 3000

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// logSlow writes one line for a request that took long or failed, so a stall
// leaves a trace. The event stream is open for as long as a page is, so it
// is left out.
func logSlow(next http.Handler, logf func(string, ...any), now func() time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if r.URL.Path == "/events" {
			return
		}
		if d := now().Sub(start); d >= slowRequest || sw.status >= 500 {
			logf("%s %s %d %s", r.Method, r.URL.Path, sw.status, d.Round(time.Millisecond))
		}
	})
}

// securityHeaders forbids other sites to frame the pages and browsers to
// guess content types, and keeps page addresses out of Referer headers sent
// elsewhere.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// newServer bounds how long a client may take to send a request. There is no
// write timeout because the dashboard event stream stays open.
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
	}
}

// maintain keeps history bounded: it fills the averaged levels and deletes
// rows past their retention, once at start and then every minute.
func maintain(ctx context.Context, st *store.Store, keep store.Retention) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		now := time.Now()
		if err := st.Rollup(ctx, now); err != nil && ctx.Err() == nil {
			log.Printf("history rollup: %v", err)
		}
		if _, err := st.Prune(ctx, now, keep); err != nil && ctx.Err() == nil {
			log.Printf("history cleanup: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func run() error {
	cfg, err := LoadConfig(os.Getenv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "fleetwatch.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := web.EnsureAdmin(ctx, st, cfg.AdminPassword); err != nil {
		return err
	}

	limit.SetTrustedProxies(cfg.TrustedProxies)
	// The Logs page shows the last lines; stderr stays the archive (docker logs).
	logs := logbuf.New(keptLogLines, time.Now)
	log.SetOutput(io.MultiWriter(os.Stderr, logs))
	bus := live.New()
	mux := http.NewServeMux()
	api.New(st, bus, time.Now).Routes(mux)
	ui, err := web.New(st, bus, logs, time.Now, cfg.PublicURL, cfg.SecureCookies())
	if err != nil {
		return err
	}
	ui.Routes(mux)
	files := dist.New(st, time.Now, cfg.PublicURL, cfg.DLDir, pubkey.PEM)
	files.Routes(mux)
	if missing := files.Missing(); len(missing) > 0 {
		log.Printf("agent files missing in %s: %v; the install line and agent upgrades will not work", cfg.DLDir, missing)
	}
	go web.NewWatcher(st, bus, time.Now).Run(ctx, 5*time.Second)
	go st.RunMetricWriter(ctx, 2*time.Second)
	go maintain(ctx, st, cfg.Retention)
	alerts := &alert.Engine{St: st, Bus: bus, Now: time.Now, Hub: web.HubName(cfg.PublicURL), Log: log.Printf}
	go alerts.Run(ctx, 15*time.Second)

	srv := newServer(cfg.Listen, securityHeaders(logSlow(mux, log.Printf, time.Now)))
	go func() {
		<-ctx.Done()
		// Dashboard streams never finish on their own, so shutdown gets a deadline.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if srv.Shutdown(shutdownCtx) != nil {
			srv.Close()
		}
	}()

	log.Printf("fleetwatch-hub listening on %s (tls=%v), public URL %s", cfg.Listen, cfg.TLS(), cfg.PublicURL)
	if cfg.TLS() {
		err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
