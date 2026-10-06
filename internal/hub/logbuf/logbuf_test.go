package logbuf

import (
	"fmt"
	"log"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 3, 14, 0, 5, 0, time.UTC)

func TestKeepsTheLastLinesInOrder(t *testing.T) {
	clock := t0
	b := New(3, func() time.Time { return clock })
	for i := 1; i <= 5; i++ {
		clock = clock.Add(time.Second)
		fmt.Fprintf(b, "line %d\n", i)
	}
	got := b.Lines()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	for i, want := range []string{"line 3", "line 4", "line 5"} {
		if got[i].Text != want || got[i].Seq != uint64(i+3) || got[i].At != t0.Add(time.Duration(i+3)*time.Second) {
			t.Errorf("line %d = %+v", i, got[i])
		}
	}
	if after := b.After(4); len(after) != 1 || after[0].Text != "line 5" {
		t.Errorf("After(4) = %+v", after)
	}
	if after := b.After(5); len(after) != 0 {
		t.Errorf("After(5) = %+v", after)
	}
	if after := b.After(900); len(after) != 3 {
		t.Errorf("a seq from before a restart must return everything, got %+v", after)
	}
	if b.Start() != t0 {
		t.Errorf("Start = %v", b.Start())
	}
}

func TestStripsTheLoggerPrefixAndSplitsLines(t *testing.T) {
	b := New(10, func() time.Time { return t0 })
	l := log.New(b, "", log.LstdFlags|log.Lmicroseconds)
	l.Printf("hello\nworld")
	l2 := log.New(b, "", log.LstdFlags)
	l2.Print("plain")
	fmt.Fprint(b, "\n\n")
	var texts []string
	for _, ln := range b.Lines() {
		texts = append(texts, ln.Text)
	}
	if strings.Join(texts, "|") != "hello|world|plain" {
		t.Errorf("texts = %q", texts)
	}
}

func TestProblemLines(t *testing.T) {
	for text, want := range map[string]bool{
		"fleetwatch-hub listening on :8080":                         false,
		"GET /hosts/1 200 1.2s":                                     false,
		"POST /login 500 3ms":                                       true,
		"POST /api/v1/report 429 1ms":                               true,
		"alerts: \"firing\" message for cpu on pinas not delivered": true,
		"history rollup: database is locked":                        false,
		"login failed from 10.0.0.9":                                true,
		"agent files missing in /dl":                                true,
		"alerts: giving up on the \"firing\" message":               true,
		"Terror in the mirror":                                      false,
		"icon for Grafana not fetched: answered HTTP 404":           true,
		"service Grafana (grafana.lan) is down: timeout":            true,
	} {
		if got := Problem(text); got != want {
			t.Errorf("Problem(%q) = %v, want %v", text, got, want)
		}
	}
	b := New(3, func() time.Time { return t0 })
	fmt.Fprintln(b, "POST /login 500 3ms")
	fmt.Fprintln(b, "report from pinas: agent 0.1.1, cpu 3%, ram 41%, disk 62%")
	fmt.Fprintln(b, "report from pinas rejected (too often)")
	got := b.Lines()
	if !got[0].Problem || got[0].Report {
		t.Errorf("failed request: %+v", got[0])
	}
	if !got[1].Report || got[1].Problem {
		t.Errorf("accepted report: %+v", got[1])
	}
	if got[2].Report || !got[2].Problem {
		t.Errorf("rejected report is a problem, not a report: %+v", got[2])
	}
}

func TestSubscribersGetNewLinesAndNeverBlockTheWriter(t *testing.T) {
	b := New(2, func() time.Time { return t0 })
	ch, cancel := b.Subscribe()
	defer cancel()
	fmt.Fprintln(b, "one")
	select {
	case ln := <-ch:
		if ln.Text != "one" || ln.Seq != 1 {
			t.Errorf("got %+v", ln)
		}
	case <-time.After(time.Second):
		t.Fatal("no line delivered")
	}
	_, cancelSlow := b.Subscribe() // never read
	defer cancelSlow()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			fmt.Fprintln(b, "flood")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked on a subscriber that does not read")
	}
	cancel()
	cancel()
	for range ch { // drains until the channel closes
	}
}

func TestTextExport(t *testing.T) {
	b := New(5, func() time.Time { return t0 })
	fmt.Fprintln(b, "first")
	fmt.Fprintln(b, "second")
	want := "2026-10-03 14:00:05 first\n2026-10-03 14:00:05 second\n"
	if got := b.Text(); got != want {
		t.Errorf("Text =\n%q\nwant\n%q", got, want)
	}
}
