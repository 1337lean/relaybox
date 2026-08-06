package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxEventBytes = 128 << 20

const (
	maxCatchUpEvents = 1_000
	maxCatchUpBytes  = 32 << 20
)

var ErrEventBacklog = errors.New("event backlog exceeds catch-up limit")

type Store struct {
	mu       sync.RWMutex
	f        *os.File
	seq      uint64
	requests map[string]Request
	attempts map[string][]Attempt
	jobs     map[string]Job
	delivery map[string]string
	body     map[string]string
	subs     map[chan Event]struct{}
	health   error
	closed   bool
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("store is not a regular file")
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	s := &Store{f: f, requests: map[string]Request{}, attempts: map[string][]Attempt{}, jobs: map[string]Job{}, delivery: map[string]string{}, body: map[string]string{}, subs: map[chan Event]struct{}{}}
	if err = s.recover(); err != nil {
		f.Close()
		return nil, err
	}
	if _, err = f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) recover() error {
	if _, err := s.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(s.f, 64<<10)
	var good int64
	for {
		line, complete, err := readRecord(r)
		if err != nil {
			return fmt.Errorf("read store at byte %d: %w", good, err)
		}
		if !complete {
			break
		}
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			return fmt.Errorf("corrupt store at byte %d", good)
		}
		if event.Seq != s.seq+1 {
			return fmt.Errorf("non-contiguous store sequence at byte %d", good)
		}
		if err := validateRecoveredEvent(event); err != nil {
			return fmt.Errorf("invalid store event at byte %d: %w", good, err)
		}
		s.apply(event)
		good += int64(len(line))
	}
	st, err := s.f.Stat()
	if err != nil {
		return err
	}
	if st.Size() != good {
		if err := s.f.Truncate(good); err != nil {
			return err
		}
	}
	return nil
}

func validateRecoveredEvent(event Event) error {
	if event.At.IsZero() {
		return errors.New("event timestamp is missing")
	}
	switch event.Kind {
	case "request.received":
		if event.Request == nil || event.Attempt != nil || event.Job != nil || event.Request.ID == "" {
			return errors.New("invalid request event payload")
		}
		sum := sha256.Sum256(event.Request.Body)
		if event.Request.BodySHA256 != hex.EncodeToString(sum[:]) {
			return errors.New("request body digest does not match")
		}
	case "attempt.finished":
		if event.Attempt == nil || event.Request != nil || event.Job != nil || event.Attempt.ID == "" || event.Attempt.JobID == "" || event.Attempt.RequestID == "" || event.Attempt.Number < 1 {
			return errors.New("invalid attempt event payload")
		}
	case "forward.queued", "forward.running", "forward.succeeded", "forward.failed", "forward.fatal", "forward.poison":
		if event.Job == nil || event.Request != nil || event.Attempt != nil || event.Job.ID == "" || event.Job.RequestID == "" {
			return errors.New("invalid job event payload")
		}
		if event.Job.State != strings.TrimPrefix(event.Kind, "forward.") {
			return errors.New("job state does not match event kind")
		}
	default:
		return fmt.Errorf("unknown event kind %q", event.Kind)
	}
	return nil
}

func readRecord(r *bufio.Reader) ([]byte, bool, error) {
	var record []byte
	total := 0
	oversized := false
	for {
		fragment, err := r.ReadSlice('\n')
		total += len(fragment)
		if total > maxEventBytes {
			oversized = true
			record = nil
		} else if !oversized {
			record = append(record, fragment...)
		}
		switch {
		case err == nil:
			if oversized {
				return nil, false, fmt.Errorf("event exceeds %d bytes", maxEventBytes)
			}
			return record, true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			// Only newline-terminated records are committed. A partial final
			// record is discarded during recovery.
			return record, false, nil
		default:
			return nil, false, err
		}
	}
}

func cloneRequest(r Request) Request {
	r.Body = append([]byte(nil), r.Body...)
	r.Headers = cloneHeader(r.Headers)
	return r
}
func cloneHeader(h Header) Header {
	out := Header{}
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}
func cloneAttempt(a Attempt) Attempt {
	a.ResponseBody = append([]byte(nil), a.ResponseBody...)
	a.ResponseHeaders = cloneHeader(a.ResponseHeaders)
	return a
}

func (s *Store) apply(e Event) {
	if e.Seq > s.seq {
		s.seq = e.Seq
	}
	if e.Request != nil {
		r := cloneRequest(*e.Request)
		s.requests[r.ID] = r
		if r.DeliveryID != "" {
			s.delivery[r.DeliveryID] = r.ID
		} else {
			s.body[r.BodySHA256] = r.ID
		}
	}
	if e.Attempt != nil {
		a := cloneAttempt(*e.Attempt)
		s.attempts[a.RequestID] = append(s.attempts[a.RequestID], a)
	}
	if e.Job != nil {
		s.jobs[e.Job.ID] = *e.Job
	}
}

func (s *Store) appendLocked(e Event) (Event, error) {
	if s.closed {
		return Event{}, os.ErrClosed
	}
	if s.health != nil {
		return Event{}, fmt.Errorf("store poisoned: %w", s.health)
	}
	s.seq++
	e.Seq = s.seq
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		s.seq--
		return Event{}, err
	}
	b = append(b, '\n')
	n, writeErr := s.f.Write(b)
	if writeErr != nil || n != len(b) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		s.health = writeErr
		return Event{}, writeErr
	}
	if err = s.f.Sync(); err != nil {
		s.health = err
		return Event{}, err
	}
	s.apply(e)
	for ch := range s.subs {
		select {
		case ch <- e:
		default:
			close(ch)
			delete(s.subs, ch)
		}
	}
	return e, nil
}
func (s *Store) Append(e Event) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendLocked(e)
}

// Capture atomically checks the idempotency key and appends the request.
func (s *Store) Capture(r Request) (string, CaptureResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.DeliveryID != "" {
		if id, ok := s.delivery[r.DeliveryID]; ok {
			if s.requests[id].BodySHA256 != r.BodySHA256 {
				return id, Conflict, nil
			}
			return id, Duplicate, nil
		}
	} else if id, ok := s.body[r.BodySHA256]; ok {
		return id, Duplicate, nil
	}
	_, err := s.appendLocked(Event{Kind: "request.received", Request: &r})
	return r.ID, Captured, err
}

func (s *Store) Get(id string) (Request, []Attempt, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.requests[id]
	if !ok {
		return Request{}, nil, false
	}
	a := make([]Attempt, len(s.attempts[id]))
	for i := range a {
		a[i] = cloneAttempt(s.attempts[id][i])
	}
	return cloneRequest(r), a, true
}
func (s *Store) ListSummaries(q string, offset, limit int) ([]RequestSummary, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	q = lower(q)
	all := make([]RequestSummary, 0, len(s.requests))
	for _, r := range s.requests {
		if q != "" && !contains(lower(r.ID+" "+r.Path+" "+r.DeliveryID+" "+string(r.Body)), q) {
			continue
		}
		all = append(all, RequestSummary{ID: r.ID, DeliveryID: r.DeliveryID, Method: r.Method, Path: r.Path, BodySHA256: r.BodySHA256, ReceivedAt: r.ReceivedAt, BodyBytes: len(r.Body)})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].ReceivedAt.Equal(all[j].ReceivedAt) {
			return all[i].ID > all[j].ID
		}
		return all[i].ReceivedAt.After(all[j].ReceivedAt)
	})
	total := len(all)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total
}
func lower(v string) string {
	b := []byte(v)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
func contains(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
func (s *Store) UnfinishedJobs() []Job {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Job{}
	for _, j := range s.jobs {
		if j.State == "queued" || j.State == "running" {
			out = append(out, j)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (s *Store) AttemptsForJob(id string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, as := range s.attempts {
		for _, a := range as {
			if a.JobID == id && a.Number > n {
				n = a.Number
			}
		}
	}
	return n
}
func (s *Store) Health() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return os.ErrClosed
	}
	return s.health
}

func (s *Store) Sequence() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seq
}

// SubscribeFrom registers before taking the snapshot, eliminating the catch-up/live race.
func (s *Store) SubscribeFrom(seq uint64) ([]Event, <-chan Event, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan Event, 128)
	s.subs[ch] = struct{}{}
	old, err := s.eventsAfterLocked(seq)
	if err != nil {
		delete(s.subs, ch)
		close(ch)
		return nil, nil, nil, err
	}
	cancel := func() {
		s.mu.Lock()
		if _, ok := s.subs[ch]; ok {
			delete(s.subs, ch)
			close(ch)
		}
		s.mu.Unlock()
	}
	return old, ch, cancel, nil
}
func (s *Store) eventsAfterLocked(seq uint64) ([]Event, error) {
	info, err := s.f.Stat()
	if err != nil {
		return nil, err
	}
	reader := io.NewSectionReader(s.f, 0, info.Size())
	var out []Event
	var catchUpBytes int
	sc := bufio.NewScanner(reader)
	sc.Buffer(make([]byte, 64<<10), maxEventBytes)
	for sc.Scan() {
		var envelope struct {
			Seq uint64 `json:"seq"`
		}
		if err := json.Unmarshal(sc.Bytes(), &envelope); err != nil {
			return nil, err
		}
		if envelope.Seq <= seq {
			continue
		}
		if len(out) == maxCatchUpEvents || catchUpBytes+len(sc.Bytes()) > maxCatchUpBytes {
			return nil, ErrEventBacklog
		}
		var event Event
		if err := json.Unmarshal(sc.Bytes(), &event); err != nil {
			return nil, err
		}
		catchUpBytes += len(sc.Bytes())
		out = append(out, event)
	}
	return out, sc.Err()
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for ch := range s.subs {
		close(ch)
		delete(s.subs, ch)
	}
	return s.f.Close()
}
