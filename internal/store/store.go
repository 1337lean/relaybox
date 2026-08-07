package store

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxEventBytes    = 128 << 20
	maxCatchUpEvents = 1_000
	maxCatchUpBytes  = 32 << 20
)

var (
	ErrCapacity     = errors.New("store retention capacity reached")
	ErrEventBacklog = errors.New("event backlog exceeds catch-up limit")
	ErrIDCollision  = errors.New("generated identifier already exists")
	ErrLeaseLost    = errors.New("forwarding lease is no longer owned")
)

type Options struct {
	MaxCaptures       int
	MaxEvents         int
	MaxJobsPerRequest int
	MaxAttemptsPerJob int
	MaxSearchBytes    int
	MaxSearchScan     int
	MaxCatchUpEvents  int
	MaxCatchUpBytes   int
	SubscriberBacklog int
}

func (o Options) withDefaults() Options {
	if o.MaxCaptures <= 0 {
		o.MaxCaptures = 1_000
	}
	if o.MaxEvents <= 0 {
		o.MaxEvents = 100_000
	}
	if o.MaxJobsPerRequest <= 0 {
		o.MaxJobsPerRequest = 8
	}
	if o.MaxAttemptsPerJob <= 0 {
		o.MaxAttemptsPerJob = 10
	}
	if o.MaxSearchBytes <= 0 {
		o.MaxSearchBytes = 64 << 10
	}
	if o.MaxSearchScan <= 0 || o.MaxSearchScan > o.MaxCaptures {
		o.MaxSearchScan = o.MaxCaptures
	}
	if o.MaxCatchUpEvents <= 0 {
		o.MaxCatchUpEvents = maxCatchUpEvents
	}
	if o.MaxCatchUpBytes <= 0 {
		o.MaxCatchUpBytes = maxCatchUpBytes
	}
	if o.SubscriberBacklog <= 0 {
		o.SubscriberBacklog = 128
	}
	return o
}

type Store struct {
	mu            sync.RWMutex
	path          string
	f             *os.File
	opts          Options
	seq           uint64
	eventCount    int
	requests      map[string]Request
	attempts      map[string][]Attempt
	attemptIDs    map[string]struct{}
	jobs          map[string]Job
	jobsByRequest map[string]map[string]struct{}
	delivery      map[string]string
	body          map[string]string
	search        map[string]string
	subs          map[chan Event]struct{}
	ring          []Event
	ringBytes     int
	health        error
	closed        bool
	beforeWrite   func(Event) error
	beforeSync    func(Event) error
}

func Open(path string) (*Store, error) {
	return OpenWithOptions(path, Options{})
}

func OpenWithOptions(path string, opts Options) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := openStoreFile(path, true)
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
	s := &Store{
		path:          path,
		f:             f,
		opts:          opts.withDefaults(),
		requests:      map[string]Request{},
		attempts:      map[string][]Attempt{},
		attemptIDs:    map[string]struct{}{},
		jobs:          map[string]Job{},
		jobsByRequest: map[string]map[string]struct{}{},
		delivery:      map[string]string{},
		body:          map[string]string{},
		search:        map[string]string{},
		subs:          map[chan Event]struct{}{},
	}
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
		if event.Seq == 0 || s.seq != 0 && event.Seq != s.seq+1 {
			return fmt.Errorf("non-contiguous store sequence at byte %d", good)
		}
		if err := validateRecoveredEvent(event); err != nil {
			return fmt.Errorf("invalid store event at byte %d: %w", good, err)
		}
		if err := s.validateStateLocked(event); err != nil {
			return fmt.Errorf("invalid store state at byte %d: %w", good, err)
		}
		s.apply(event)
		s.eventCount++
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
	for _, id := range append(append([]string(nil), event.EvictedRequestIDs...), event.EvictedJobIDs...) {
		if id == "" {
			return errors.New("empty eviction identifier")
		}
	}
	switch event.Kind {
	case "capture.accepted":
		if event.Request == nil || event.Attempt != nil || event.Request.ID == "" {
			return errors.New("invalid capture event payload")
		}
		if event.Job != nil && (event.Job.ID == "" || event.Job.RequestID != event.Request.ID || event.Job.State != "pending") {
			return errors.New("invalid capture job payload")
		}
		return validateRequestDigest(*event.Request)
	case "request.received":
		if event.Request == nil || event.Attempt != nil || event.Job != nil || event.Request.ID == "" {
			return errors.New("invalid request event payload")
		}
		return validateRequestDigest(*event.Request)
	case "attempt.finished":
		if event.Attempt == nil || event.Request != nil || event.Job != nil {
			return errors.New("invalid attempt event payload")
		}
		return validateAttempt(*event.Attempt)
	case "forward.pending", "forward.queued", "forward.running", "forward.leased", "forward.retrying", "forward.succeeded", "forward.failed", "forward.fatal", "forward.dead-letter", "forward.poison":
		if event.Job == nil || event.Request != nil || event.Job.ID == "" || event.Job.RequestID == "" {
			return errors.New("invalid job event payload")
		}
		if event.Job.State != strings.TrimPrefix(event.Kind, "forward.") {
			return errors.New("job state does not match event kind")
		}
		if event.Attempt != nil {
			if err := validateAttempt(*event.Attempt); err != nil {
				return err
			}
			if event.Attempt.JobID != event.Job.ID || event.Attempt.RequestID != event.Job.RequestID {
				return errors.New("attempt does not belong to job")
			}
		}
	default:
		return fmt.Errorf("unknown event kind %q", event.Kind)
	}
	return nil
}

func validateRequestDigest(r Request) error {
	sum := sha256.Sum256(r.Body)
	if r.BodySHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("request body digest does not match")
	}
	return nil
}

func validateAttempt(a Attempt) error {
	if a.ID == "" || a.JobID == "" || a.RequestID == "" || a.Number < 1 {
		return errors.New("invalid attempt payload")
	}
	return nil
}

func (s *Store) validateStateLocked(event Event) error {
	if event.Request != nil {
		if _, exists := s.requests[event.Request.ID]; exists {
			return fmt.Errorf("request %q is duplicated", event.Request.ID)
		}
	}
	if event.Job != nil {
		if existing, exists := s.jobs[event.Job.ID]; exists {
			if existing.RequestID != event.Job.RequestID || existing.URL != event.Job.URL {
				return fmt.Errorf("job %q changed immutable identity", event.Job.ID)
			}
		} else if _, requestExists := s.requests[event.Job.RequestID]; !requestExists && (event.Request == nil || event.Request.ID != event.Job.RequestID) {
			return fmt.Errorf("job %q refers to a missing request", event.Job.ID)
		}
	}
	if event.Attempt != nil {
		if _, exists := s.attemptIDs[event.Attempt.ID]; exists {
			return fmt.Errorf("attempt %q is duplicated", event.Attempt.ID)
		}
		if _, exists := s.requests[event.Attempt.RequestID]; !exists && (event.Request == nil || event.Request.ID != event.Attempt.RequestID) {
			return fmt.Errorf("attempt %q refers to a missing request", event.Attempt.ID)
		}
		if _, exists := s.jobs[event.Attempt.JobID]; !exists && (event.Job == nil || event.Job.ID != event.Attempt.JobID) {
			return fmt.Errorf("attempt %q refers to a missing job", event.Attempt.ID)
		}
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
			return record, false, nil
		default:
			return nil, false, err
		}
	}
}

func cloneHeader(h Header) Header {
	out := Header{}
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func cloneRequest(r Request) Request {
	r.Body = append([]byte(nil), r.Body...)
	r.Headers = cloneHeader(r.Headers)
	return r
}

func cloneAttempt(a Attempt) Attempt {
	a.ResponseBody = append([]byte(nil), a.ResponseBody...)
	a.ResponseHeaders = cloneHeader(a.ResponseHeaders)
	return a
}

func cloneEvent(e Event) Event {
	if e.Request != nil {
		r := cloneRequest(*e.Request)
		e.Request = &r
	}
	if e.Attempt != nil {
		a := cloneAttempt(*e.Attempt)
		e.Attempt = &a
	}
	if e.Job != nil {
		j := *e.Job
		e.Job = &j
	}
	e.EvictedRequestIDs = append([]string(nil), e.EvictedRequestIDs...)
	e.EvictedJobIDs = append([]string(nil), e.EvictedJobIDs...)
	return e
}

func (s *Store) apply(e Event) {
	if e.Seq > s.seq {
		s.seq = e.Seq
	}
	for _, id := range e.EvictedJobIDs {
		s.removeJob(id)
	}
	for _, id := range e.EvictedRequestIDs {
		s.removeRequest(id)
	}
	if e.Request != nil {
		r := cloneRequest(*e.Request)
		s.requests[r.ID] = r
		if r.DeliveryID != "" {
			s.delivery[r.DeliveryID] = r.ID
		} else {
			s.body[r.BodySHA256] = r.ID
		}
		searchBody := r.Body
		if len(searchBody) > s.opts.MaxSearchBytes {
			searchBody = searchBody[:s.opts.MaxSearchBytes]
		}
		s.search[r.ID] = lower(r.ID + " " + r.Path + " " + r.DeliveryID + " " + string(searchBody))
	}
	if e.Attempt != nil {
		a := cloneAttempt(*e.Attempt)
		s.attempts[a.RequestID] = append(s.attempts[a.RequestID], a)
		s.attemptIDs[a.ID] = struct{}{}
	}
	if e.Job != nil {
		j := *e.Job
		s.jobs[j.ID] = j
		if s.jobsByRequest[j.RequestID] == nil {
			s.jobsByRequest[j.RequestID] = map[string]struct{}{}
		}
		s.jobsByRequest[j.RequestID][j.ID] = struct{}{}
	}
	s.appendRing(e)
}

func (s *Store) appendRing(e Event) {
	b, _ := json.Marshal(e)
	s.ring = append(s.ring, cloneEvent(e))
	s.ringBytes += len(b)
	for len(s.ring) > s.opts.MaxCatchUpEvents || s.ringBytes > s.opts.MaxCatchUpBytes {
		old, _ := json.Marshal(s.ring[0])
		s.ringBytes -= len(old)
		s.ring = s.ring[1:]
	}
}

func (s *Store) removeRequest(id string) {
	r, ok := s.requests[id]
	if !ok {
		return
	}
	if r.DeliveryID != "" && s.delivery[r.DeliveryID] == id {
		delete(s.delivery, r.DeliveryID)
	}
	if r.DeliveryID == "" && s.body[r.BodySHA256] == id {
		delete(s.body, r.BodySHA256)
	}
	for jobID := range s.jobsByRequest[id] {
		s.removeJob(jobID)
	}
	delete(s.jobsByRequest, id)
	delete(s.requests, id)
	for _, a := range s.attempts[id] {
		delete(s.attemptIDs, a.ID)
	}
	delete(s.attempts, id)
	delete(s.search, id)
}

func (s *Store) removeJob(id string) {
	j, ok := s.jobs[id]
	if !ok {
		return
	}
	delete(s.jobs, id)
	if byRequest := s.jobsByRequest[j.RequestID]; byRequest != nil {
		delete(byRequest, id)
		if len(byRequest) == 0 {
			delete(s.jobsByRequest, j.RequestID)
		}
	}
	attempts := s.attempts[j.RequestID]
	kept := attempts[:0]
	for _, a := range attempts {
		if a.JobID != id {
			kept = append(kept, a)
		} else {
			delete(s.attemptIDs, a.ID)
		}
	}
	if len(kept) == 0 {
		delete(s.attempts, j.RequestID)
	} else {
		s.attempts[j.RequestID] = kept
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
	if err := validateRecoveredEvent(e); err != nil {
		s.seq--
		return Event{}, err
	}
	if err := s.validateStateLocked(e); err != nil {
		s.seq--
		return Event{}, err
	}
	if s.beforeWrite != nil {
		if err := s.beforeWrite(cloneEvent(e)); err != nil {
			s.seq--
			s.health = err
			return Event{}, err
		}
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
	if s.beforeSync != nil {
		if err = s.beforeSync(cloneEvent(e)); err != nil {
			s.health = err
			return Event{}, err
		}
	}
	if err = s.f.Sync(); err != nil {
		s.health = err
		return Event{}, err
	}
	s.apply(e)
	s.eventCount++
	if s.eventCount > s.opts.MaxEvents {
		if err := s.compactLocked(); err != nil {
			s.health = err
			return Event{}, err
		}
	}
	for ch := range s.subs {
		select {
		case ch <- cloneEvent(e):
		default:
			close(ch)
			delete(s.subs, ch)
		}
	}
	return cloneEvent(e), nil
}

func (s *Store) Append(e Event) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendLocked(e)
}

// Accept atomically checks idempotency and persists a capture with its required
// forwarding intent in one synced event record.
func (s *Store) Accept(r Request, job *Job) (string, CaptureResult, *Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, result, ok := s.duplicateLocked(r); ok {
		return id, result, s.discoverableJobLocked(id), nil
	}
	if _, exists := s.requests[r.ID]; exists {
		return "", Captured, nil, fmt.Errorf("request: %w", ErrIDCollision)
	}
	if job != nil && (job.RequestID != r.ID || job.State != "pending") {
		return "", Captured, nil, errors.New("invalid capture forwarding intent")
	}
	if job != nil {
		if _, exists := s.jobs[job.ID]; exists {
			return "", Captured, nil, fmt.Errorf("job: %w", ErrIDCollision)
		}
	}
	evictions, err := s.captureEvictionsLocked(1)
	if err != nil {
		return "", Captured, nil, err
	}
	e := Event{Kind: "capture.accepted", Request: &r, Job: job, EvictedRequestIDs: evictions}
	if _, err := s.appendLocked(e); err != nil {
		return "", Captured, nil, err
	}
	var persisted *Job
	if job != nil {
		j := *job
		persisted = &j
	}
	return r.ID, Captured, persisted, nil
}

// Capture preserves the no-forwarding store API used by callers and tests.
func (s *Store) Capture(r Request) (string, CaptureResult, error) {
	id, result, _, err := s.Accept(r, nil)
	return id, result, err
}

func (s *Store) duplicateLocked(r Request) (string, CaptureResult, bool) {
	if r.DeliveryID != "" {
		if id, ok := s.delivery[r.DeliveryID]; ok {
			if s.requests[id].BodySHA256 != r.BodySHA256 {
				return id, Conflict, true
			}
			return id, Duplicate, true
		}
	} else if id, ok := s.body[r.BodySHA256]; ok {
		return id, Duplicate, true
	}
	return "", Captured, false
}

func (s *Store) discoverableJobLocked(requestID string) *Job {
	var selected *Job
	for id := range s.jobsByRequest[requestID] {
		j := s.jobs[id]
		if selected == nil || terminalState(selected.State) && !terminalState(j.State) || terminalState(selected.State) == terminalState(j.State) && j.CreatedAt.Before(selected.CreatedAt) {
			copy := j
			selected = &copy
		}
	}
	return selected
}

func (s *Store) captureEvictionsLocked(required int) ([]string, error) {
	over := len(s.requests) + required - s.opts.MaxCaptures
	if over <= 0 {
		return nil, nil
	}
	candidates := make([]Request, 0, len(s.requests))
	for _, r := range s.requests {
		if s.requestTerminalLocked(r.ID) {
			candidates = append(candidates, r)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ReceivedAt.Before(candidates[j].ReceivedAt) })
	if len(candidates) < over {
		return nil, ErrCapacity
	}
	ids := make([]string, over)
	for i := range ids {
		ids[i] = candidates[i].ID
	}
	return ids, nil
}

func (s *Store) requestTerminalLocked(requestID string) bool {
	for id := range s.jobsByRequest[requestID] {
		if !terminalState(s.jobs[id].State) {
			return false
		}
	}
	return true
}

func terminalState(state string) bool {
	switch state {
	case "succeeded", "failed", "fatal", "dead-letter", "poison":
		return true
	default:
		return false
	}
}

func (s *Store) Enqueue(j Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.requests[j.RequestID]; !ok {
		return errors.New("request missing")
	}
	if j.State != "pending" {
		return errors.New("new job must be pending")
	}
	if _, exists := s.jobs[j.ID]; exists {
		return fmt.Errorf("job: %w", ErrIDCollision)
	}
	var evicted []string
	if len(s.jobsByRequest[j.RequestID]) >= s.opts.MaxJobsPerRequest {
		var candidates []Job
		for id := range s.jobsByRequest[j.RequestID] {
			candidate := s.jobs[id]
			if terminalState(candidate.State) {
				candidates = append(candidates, candidate)
			}
		}
		if len(candidates) == 0 {
			return ErrCapacity
		}
		sort.Slice(candidates, func(i, k int) bool { return candidates[i].CreatedAt.Before(candidates[k].CreatedAt) })
		evicted = []string{candidates[0].ID}
	}
	_, err := s.appendLocked(Event{Kind: "forward.pending", Job: &j, EvictedJobIDs: evicted})
	return err
}

func (s *Store) ClaimNextJob(owner string, now time.Time, lease time.Duration) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var candidates []Job
	for _, j := range s.jobs {
		eligible := j.State == "pending" || j.State == "queued" || j.State == "retrying" && !j.AvailableAt.After(now) || (j.State == "leased" || j.State == "running") && (j.LeaseExpiresAt.IsZero() || !j.LeaseExpiresAt.After(now))
		if eligible {
			candidates = append(candidates, j)
		}
	}
	if len(candidates) == 0 {
		return Job{}, false, nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].AvailableAt.Equal(candidates[j].AvailableAt) {
			return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
		}
		return candidates[i].AvailableAt.Before(candidates[j].AvailableAt)
	})
	j := candidates[0]
	j.State = "leased"
	j.LeaseOwner = owner
	j.LeaseExpiresAt = now.Add(lease)
	j.UpdatedAt = now
	if _, err := s.appendLocked(Event{Kind: "forward.leased", Job: &j}); err != nil {
		return Job{}, false, err
	}
	return j, true, nil
}

// RecoverLeases makes work owned by a previous process immediately claimable.
// Relaybox permits only one process per store, so no live owner can survive a
// process restart.
func (s *Store) RecoverLeases(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var stale []Job
	for _, j := range s.jobs {
		if j.State == "leased" || j.State == "running" {
			stale = append(stale, j)
		}
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].CreatedAt.Before(stale[j].CreatedAt) })
	for _, j := range stale {
		j.State = "pending"
		j.Error = ""
		j.LeaseOwner = ""
		j.LeaseExpiresAt = time.Time{}
		j.AvailableAt = now
		j.UpdatedAt = now
		if _, err := s.appendLocked(Event{Kind: "forward.pending", Job: &j}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) RecordAttempt(jobID, owner string, attempt Attempt, state, message string, availableAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok || j.State != "leased" || j.LeaseOwner != owner {
		return ErrLeaseLost
	}
	if attempt.Number > s.opts.MaxAttemptsPerJob {
		return ErrCapacity
	}
	expectedAttempt := 1
	for _, existing := range s.attempts[j.RequestID] {
		if existing.JobID == jobID && existing.Number >= expectedAttempt {
			expectedAttempt = existing.Number + 1
		}
	}
	if attempt.Number != expectedAttempt {
		return fmt.Errorf("attempt number %d is not next expected number %d", attempt.Number, expectedAttempt)
	}
	if _, exists := s.attemptIDs[attempt.ID]; exists {
		return fmt.Errorf("attempt: %w", ErrIDCollision)
	}
	switch state {
	case "retrying", "succeeded", "fatal", "dead-letter":
	default:
		return errors.New("invalid attempt result state")
	}
	now := attempt.FinishedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	j.State = state
	j.Error = message
	j.UpdatedAt = now
	j.LeaseOwner = ""
	j.LeaseExpiresAt = time.Time{}
	j.AvailableAt = availableAt
	if terminalState(state) {
		j.FinishedAt = now
	}
	_, err := s.appendLocked(Event{Kind: "forward." + state, Attempt: &attempt, Job: &j})
	return err
}

func (s *Store) FinishWithoutAttempt(jobID, owner, state, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok || j.State != "leased" || j.LeaseOwner != owner {
		return ErrLeaseLost
	}
	if state != "poison" {
		return errors.New("invalid no-attempt state")
	}
	now := time.Now().UTC()
	j.State = state
	j.Error = message
	j.UpdatedAt = now
	j.FinishedAt = now
	j.LeaseOwner = ""
	j.LeaseExpiresAt = time.Time{}
	_, err := s.appendLocked(Event{Kind: "forward." + state, Job: &j})
	return err
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

type searchRecord struct {
	summary RequestSummary
	index   string
}

func (s *Store) ListSummariesContext(ctx context.Context, q string, offset, limit int) ([]RequestSummary, int, bool, error) {
	select {
	case <-ctx.Done():
		return nil, 0, false, ctx.Err()
	default:
	}
	s.mu.RLock()
	all := make([]searchRecord, 0, min(len(s.requests), s.opts.MaxSearchScan))
	for id, r := range s.requests {
		if len(all) == s.opts.MaxSearchScan {
			break
		}
		all = append(all, searchRecord{
			summary: RequestSummary{ID: r.ID, DeliveryID: r.DeliveryID, Method: r.Method, Path: r.Path, BodySHA256: r.BodySHA256, ReceivedAt: r.ReceivedAt, BodyBytes: len(r.Body)},
			index:   s.search[id],
		})
	}
	truncated := len(s.requests) > len(all)
	s.mu.RUnlock()

	q = lower(q)
	matched := make([]RequestSummary, 0, len(all))
	for i, record := range all {
		if i%64 == 0 {
			select {
			case <-ctx.Done():
				return nil, 0, truncated, ctx.Err()
			default:
			}
		}
		if q == "" || strings.Contains(record.index, q) {
			matched = append(matched, record.summary)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].ReceivedAt.Equal(matched[j].ReceivedAt) {
			return matched[i].ID > matched[j].ID
		}
		return matched[i].ReceivedAt.After(matched[j].ReceivedAt)
	})
	total := len(matched)
	if offset > total {
		offset = total
	}
	end := min(offset+limit, total)
	return matched[offset:end], total, truncated, nil
}

func (s *Store) ListSummaries(q string, offset, limit int) ([]RequestSummary, int) {
	items, total, _, _ := s.ListSummariesContext(context.Background(), q, offset, limit)
	return items, total
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

func (s *Store) UnfinishedJobs() []Job {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Job{}
	for _, j := range s.jobs {
		if !terminalState(j.State) {
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

func (s *Store) JobCounts() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]int{"pending": 0, "leased": 0, "retrying": 0, "succeeded": 0, "failed": 0, "fatal": 0, "dead-letter": 0, "poison": 0}
	for _, j := range s.jobs {
		state := j.State
		if state == "queued" {
			state = "pending"
		}
		if state == "running" {
			state = "leased"
		}
		out[state]++
	}
	return out
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

func (s *Store) SubscribeFrom(seq uint64) ([]Event, <-chan Event, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan Event, s.opts.SubscriberBacklog)
	if len(s.ring) > 0 {
		oldest := s.ring[0].Seq
		if seq < oldest && oldest-seq > 1 {
			close(ch)
			return nil, nil, nil, ErrEventBacklog
		}
	}
	old := make([]Event, 0, len(s.ring))
	for _, e := range s.ring {
		if e.Seq > seq {
			old = append(old, cloneEvent(e))
		}
	}
	s.subs[ch] = struct{}{}
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

func (s *Store) compactLocked() error {
	records := s.snapshotRecordsLocked()
	if len(records) == 0 {
		return nil
	}
	start := s.seq - uint64(len(records)) + 1
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".relaybox-compact-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return err
	}
	w := bufio.NewWriterSize(tmp, 64<<10)
	for i := range records {
		records[i].Seq = start + uint64(i)
		if err := json.NewEncoder(w).Encode(records[i]); err != nil {
			cleanup()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}
	newFile, err := openStoreFile(s.path, false)
	if err != nil {
		return err
	}
	if _, err := newFile.Seek(0, io.SeekEnd); err != nil {
		newFile.Close()
		return err
	}
	old := s.f
	s.f = newFile
	s.eventCount = len(records)
	return old.Close()
}

func (s *Store) snapshotRecordsLocked() []Event {
	requestIDs := make([]string, 0, len(s.requests))
	for id := range s.requests {
		requestIDs = append(requestIDs, id)
	}
	sort.Slice(requestIDs, func(i, j int) bool {
		return s.requests[requestIDs[i]].ReceivedAt.Before(s.requests[requestIDs[j]].ReceivedAt)
	})
	var records []Event
	for _, id := range requestIDs {
		r := cloneRequest(s.requests[id])
		at := r.ReceivedAt
		if at.IsZero() {
			at = time.Unix(0, 1).UTC()
		}
		records = append(records, Event{Kind: "request.received", At: at, Request: &r})
		jobIDs := make([]string, 0, len(s.jobsByRequest[id]))
		for jobID := range s.jobsByRequest[id] {
			jobIDs = append(jobIDs, jobID)
		}
		sort.Strings(jobIDs)
		for _, jobID := range jobIDs {
			j := s.jobs[jobID]
			at := j.UpdatedAt
			if at.IsZero() {
				at = j.CreatedAt
			}
			if at.IsZero() {
				at = time.Unix(0, 1).UTC()
			}
			records = append(records, Event{Kind: "forward." + j.State, At: at, Job: &j})
		}
		for _, original := range s.attempts[id] {
			a := cloneAttempt(original)
			at := a.FinishedAt
			if at.IsZero() {
				at = time.Unix(0, 1).UTC()
			}
			records = append(records, Event{Kind: "attempt.finished", At: at, Attempt: &a})
		}
	}
	return records
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
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
