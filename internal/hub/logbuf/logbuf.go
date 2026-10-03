// Package logbuf keeps the Hub's most recent log lines in memory for the
// Logs page and hands new lines to open pages.
package logbuf

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type Line struct {
	Seq     uint64
	At      time.Time
	Text    string
	Problem bool // the line reports something that went wrong
	Report  bool // an accepted agent report; frequent, so the page can hide them
}

type Buffer struct {
	now   func() time.Time
	start time.Time

	mu   sync.Mutex
	ring []Line
	next int // ring index the next line goes to
	n    int
	seq  uint64
	subs map[chan Line]struct{}
}

func New(size int, now func() time.Time) *Buffer {
	return &Buffer{now: now, start: now(), ring: make([]Line, size), subs: map[chan Line]struct{}{}}
}

// stdPrefix is the date and time the standard logger puts first; the page
// shows its own time instead.
var stdPrefix = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? `)

// Write stores every non-empty line in p. It never blocks on a reader.
func (b *Buffer) Write(p []byte) (int, error) {
	at := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, text := range strings.Split(string(p), "\n") {
		text = strings.TrimRight(stdPrefix.ReplaceAllString(text, ""), "\r")
		if text == "" {
			continue
		}
		b.seq++
		ln := Line{Seq: b.seq, At: at, Text: text, Problem: Problem(text)}
		ln.Report = !ln.Problem && strings.HasPrefix(text, "report from ")
		b.ring[b.next] = ln
		b.next = (b.next + 1) % len(b.ring)
		if b.n < len(b.ring) {
			b.n++
		}
		for ch := range b.subs {
			select {
			case ch <- ln:
			default:
			}
		}
	}
	return len(p), nil
}

// Start is when the buffer was made, which is when the Hub started.
func (b *Buffer) Start() time.Time { return b.start }

// Size is how many lines the buffer keeps at most.
func (b *Buffer) Size() int { return len(b.ring) }

// Lines returns the kept lines, oldest first.
func (b *Buffer) Lines() []Line {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Line, 0, b.n)
	first := (b.next - b.n + len(b.ring)) % len(b.ring)
	for i := 0; i < b.n; i++ {
		out = append(out, b.ring[(first+i)%len(b.ring)])
	}
	return out
}

// After returns the kept lines written after the one with sequence seq. A
// seq this buffer has not reached belongs to a Hub run before a restart, so
// every kept line is new to the caller.
func (b *Buffer) After(seq uint64) []Line {
	all := b.Lines()
	if n := len(all); n > 0 && seq > all[n-1].Seq {
		return all
	}
	for i, ln := range all {
		if ln.Seq > seq {
			return all[i:]
		}
	}
	return nil
}

// Subscribe delivers each new line; a subscriber that does not read loses lines.
func (b *Buffer) Subscribe() (<-chan Line, func()) {
	ch := make(chan Line, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, ch)
			close(ch)
			b.mu.Unlock()
		})
	}
}

// Text is the kept log as plain text, one line each with its time.
func (b *Buffer) Text() string {
	var sb strings.Builder
	for _, ln := range b.Lines() {
		sb.WriteString(ln.At.Format("2006-01-02 15:04:05"))
		sb.WriteByte(' ')
		sb.WriteString(ln.Text)
		sb.WriteByte('\n')
	}
	return sb.String()
}

var (
	problemWords = regexp.MustCompile(`(?i)\b(?:error|failed|refused|rejected|missing|panic)\b|not delivered|giving up`)
	// A request line: method, path, status, duration.
	failedRequest = regexp.MustCompile(`^[A-Z]+ \S+ (?:429|5\d\d) `)
)

// Problem reports whether a line says something went wrong.
func Problem(text string) bool {
	return problemWords.MatchString(text) || failedRequest.MatchString(text)
}
