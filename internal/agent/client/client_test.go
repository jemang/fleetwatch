package client

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"fleetwatch/internal/protocol"
)

func TestSendSuccess(t *testing.T) {
	var gotAuth, gotPath, gotEncoding string
	var got protocol.Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotEncoding = r.Header.Get("Authorization"), r.URL.Path, r.Header.Get("Content-Encoding")
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("report body must be gzip: %v", err)
			return
		}
		b, _ := io.ReadAll(zr)
		json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	err := New(srv.URL+"/", "tok").Send(context.Background(), protocol.Report{ProtocolVersion: 1, TS: 42})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok" || gotPath != "/api/v1/agent/report" || gotEncoding != "gzip" || got.TS != 42 {
		t.Errorf("auth=%q path=%q encoding=%q report=%+v", gotAuth, gotPath, gotEncoding, got)
	}
}

func TestSendErrorKinds(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusUnauthorized)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := int(status.Load())
		w.WriteHeader(code)
		if code == http.StatusConflict {
			json.NewEncoder(w).Encode(protocol.ReplayResponse{LastTS: 99})
		}
	}))
	c := New(srv.URL, "tok")

	if err := c.Send(context.Background(), protocol.Report{}); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("401: err = %v, want ErrUnauthorized", err)
	}
	status.Store(http.StatusConflict)
	var replay *ReplayError
	if err := c.Send(context.Background(), protocol.Report{}); !errors.As(err, &replay) || replay.LastTS != 99 {
		t.Errorf("409: err = %v, want ReplayError with LastTS 99", err)
	}
	status.Store(http.StatusInternalServerError)
	var se *StatusError
	if err := c.Send(context.Background(), protocol.Report{}); !errors.As(err, &se) || se.Code != 500 {
		t.Errorf("500: err = %v, want StatusError 500", err)
	}
	srv.Close()
	err := c.Send(context.Background(), protocol.Report{})
	se = nil
	if err == nil || errors.As(err, &se) || errors.Is(err, ErrUnauthorized) {
		t.Errorf("unreachable Hub: err = %v, want a plain transport error", err)
	}
}

func TestSendNeverFollowsRedirects(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	var se *StatusError
	err := New(srv.URL, "tok").Send(context.Background(), protocol.Report{})
	if !errors.As(err, &se) || se.Code != http.StatusTemporaryRedirect || hits.Load() != 0 {
		t.Errorf("err = %v, redirect target hits = %d; the token must not travel to a redirect target", err, hits.Load())
	}
}

func TestEnroll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)
		if r.URL.Path != "/api/v1/agent/enroll" || req.Token != "good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(protocol.EnrollResponse{AgentID: "5", AgentToken: "permanent"})
	}))
	defer srv.Close()
	c := New(srv.URL, "")
	resp, err := c.Enroll(context.Background(), protocol.EnrollRequest{Token: "good", Hostname: "web-01"})
	if err != nil || resp.AgentID != "5" || resp.AgentToken != "permanent" {
		t.Errorf("enroll = %+v, %v", resp, err)
	}
	if _, err := c.Enroll(context.Background(), protocol.EnrollRequest{Token: "bad"}); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("rejected token: err = %v, want ErrUnauthorized", err)
	}
}
