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
	mu sync.RWMutex
	// fileMu protects the lifetime of f while body payloads are read with
	// ReadAt. Lock ordering is always mu, then fileMu. Ordinary appends can run
	// alongside payload reads; compaction and Close take the exclusive lock
	// before replacing or closing the descriptor.
	fileMu        sync.RWMutex
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
	requestRecord map[string]recordRef
	requestBytes  map[string]int
	attemptRecord map[string]recordRef
	search        map[string]string
	subs          map[chan Event]struct{}
	ring          []Event
	ringBytes     int
	health        error
	closed        bool
	beforeWrite   func(Event) error
	beforeSync    func(Event) error
}

type recordRef struct {
	offset int64
	length int
	seq    uint64
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
		requestRecord: map[string]recordRef{},
		requestBytes:  map[string]int{},
		attemptRecord: map[string]recordRef{},
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
	seenMutation := false
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
		if event.Snapshot {
			if seenMutation {
				return fmt.Errorf("invalid store snapshot at byte %d: snapshot record follows a mutation", good)
			}
		} else {
			seenMutation = true
			s.eventCount++
		}
		s.apply(event, recordRef{offset: good, length: len(line), seq: event.Seq})
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

func (s *Store) apply(e Event, ref recordRef) {
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
		body := r.Body
		r.Body = nil
		s.requests[r.ID] = r
		s.requestRecord[r.ID] = ref
		s.requestBytes[r.ID] = len(body)
		if r.DeliveryID != "" {
			s.delivery[r.DeliveryID] = r.ID
		} else {
			s.body[r.BodySHA256] = r.ID
		}
		searchBody := body
		if len(searchBody) > s.opts.MaxSearchBytes {
			searchBody = searchBody[:s.opts.MaxSearchBytes]
		}
		s.search[r.ID] = lower(r.ID + " " + r.Path + " " + r.DeliveryID + " " + string(searchBody))
	}
	if e.Attempt != nil {
		a := cloneAttempt(*e.Attempt)
		a.ResponseBody = nil
		s.attempts[a.RequestID] = append(s.attempts[a.RequestID], a)
		s.attemptIDs[a.ID] = struct{}{}
		s.attemptRecord[a.ID] = ref
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
		delete(s.attemptRecord, a.ID)
	}
	delete(s.attempts, id)
	delete(s.requestRecord, id)
	delete(s.requestBytes, id)
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
			delete(s.attemptRecord, a.ID)
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
	// Snapshot is storage metadata assigned only while compaction rewrites the
	// current state. Callers cannot turn ordinary mutations into snapshot data.
	e.Snapshot = false
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
	if len(b) > maxEventBytes {
		s.seq--
		return Event{}, fmt.Errorf("event exceeds %d bytes", maxEventBytes)
	}
	offset, err := s.f.Seek(0, io.SeekCurrent)
	if err != nil {
		s.seq--
		return Event{}, err
	}
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
	s.apply(e, recordRef{offset: offset, length: len(b), seq: e.Seq})
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
	if job != nil && (job.ID == "" || job.RequestID != r.ID || job.State != "pending") {
		return "", Captured, nil, errors.New("invalid capture forwarding intent")
	}
	if id, result, ok := s.duplicateLocked(r); ok {
		persisted := s.discoverableJobLocked(id)
		// Stores created before atomic capture intents (and captures accepted
		// while forwarding was disabled) can legitimately have no job. A
		// duplicate delivered after forwarding is configured repairs that legacy
		// state under the same idempotency lock instead of acknowledging a request
		// that still has no discoverable delivery intent.
		if result == Duplicate && job != nil && persisted == nil {
			if _, exists := s.jobs[job.ID]; exists {
				return id, result, nil, fmt.Errorf("job: %w", ErrIDCollision)
			}
			repaired := *job
			repaired.RequestID = id
			if _, err := s.appendLocked(Event{Kind: "forward.pending", Job: &repaired}); err != nil {
				return id, result, nil, err
			}
			persisted = &repaired
		}
		return id, result, persisted, nil
	}
	if _, exists := s.requests[r.ID]; exists {
		return "", Captured, nil, fmt.Errorf("request: %w", ErrIDCollision)
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

// Load returns one capture and its attempts. Payload bytes are loaded on
// demand from the already-open append log so startup and steady-state memory
// retain metadata and bounded search prefixes rather than every body.
func (s *Store) Load(id string) (Request, []Attempt, bool, error) {
	s.mu.RLock()
	r, ok := s.requests[id]
	if !ok {
		s.mu.RUnlock()
		return Request{}, nil, false, nil
	}
	r = cloneRequest(r)
	requestRef := s.requestRecord[id]
	attempts := make([]Attempt, len(s.attempts[id]))
	attemptRefs := make([]recordRef, len(attempts))
	for i := range attempts {
		attempts[i] = cloneAttempt(s.attempts[id][i])
		attemptRefs[i] = s.attemptRecord[attempts[i].ID]
	}
	// Acquire fileMu before releasing mu so compaction cannot swap and close
	// the descriptor between the metadata snapshot and the corresponding
	// positional reads.
	s.fileMu.RLock()
	f := s.f
	s.mu.RUnlock()

	loadErr := func() error {
		defer s.fileMu.RUnlock()
		event, err := readEventAt(f, requestRef)
		if err != nil {
			return fmt.Errorf("load request %q: %w", id, err)
		}
		if event.Request == nil || event.Request.ID != id {
			return fmt.Errorf("load request %q: store record identity changed", id)
		}
		if err := validateRequestDigest(*event.Request); err != nil {
			return fmt.Errorf("load request %q: %w", id, err)
		}
		r.Body = append([]byte(nil), event.Request.Body...)
		for i := range attempts {
			event, err := readEventAt(f, attemptRefs[i])
			if err != nil {
				return fmt.Errorf("load attempt %q: %w", attempts[i].ID, err)
			}
			if event.Attempt == nil || event.Attempt.ID != attempts[i].ID {
				return fmt.Errorf("load attempt %q: store record identity changed", attempts[i].ID)
			}
			attempts[i].ResponseBody = append([]byte(nil), event.Attempt.ResponseBody...)
		}
		return nil
	}()
	if loadErr != nil {
		s.poison(loadErr)
		return Request{}, nil, false, loadErr
	}
	return r, attempts, true, nil
}

// Get is retained for callers that only need the historical boolean lookup
// API. Production request and forwarding paths use Load so I/O failures are
// surfaced rather than mistaken for a missing capture.
func (s *Store) Get(id string) (Request, []Attempt, bool) {
	r, attempts, ok, _ := s.Load(id)
	return r, attempts, ok
}

// RedactHeaders replaces matching retained request and attempt header values
// and compacts the store when a legacy plaintext value is found. The caller
// supplies the policy so application-specific header names are migrated too.
func (s *Store) RedactHeaders(sensitive func(string) bool) error {
	if sensitive == nil {
		return errors.New("sensitive header policy is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return os.ErrClosed
	}
	if s.health != nil {
		return fmt.Errorf("store poisoned: %w", s.health)
	}
	redact := func(headers Header) bool {
		changed := false
		for name, values := range headers {
			if sensitive(name) && (len(values) != 1 || values[0] != "[REDACTED]") {
				headers[name] = []string{"[REDACTED]"}
				changed = true
			}
		}
		return changed
	}
	changed := false
	for id, request := range s.requests {
		if redact(request.Headers) {
			s.requests[id] = request
			changed = true
		}
	}
	for requestID, attempts := range s.attempts {
		for i := range attempts {
			if redact(attempts[i].ResponseHeaders) {
				changed = true
			}
		}
		s.attempts[requestID] = attempts
	}
	// Recovery also populates the SSE catch-up ring from the legacy log. Keep
	// that in-memory presentation path redacted even if compaction cannot run.
	for i := range s.ring {
		if s.ring[i].Request != nil && redact(s.ring[i].Request.Headers) {
			changed = true
		}
		if s.ring[i].Attempt != nil && redact(s.ring[i].Attempt.ResponseHeaders) {
			changed = true
		}
	}
	if changed {
		s.recountRingLocked()
	}
	if !changed {
		var err error
		changed, err = s.logNeedsHeaderRedactionLocked(sensitive)
		if err != nil {
			s.health = err
			return fmt.Errorf("scan legacy headers: %w", err)
		}
	}
	if !changed {
		return nil
	}
	if err := s.compactLocked(); err != nil {
		s.health = err
		return fmt.Errorf("compact redacted store: %w", err)
	}
	return nil
}

func (s *Store) recountRingLocked() {
	s.ringBytes = 0
	for _, event := range s.ring {
		encoded, _ := json.Marshal(event)
		s.ringBytes += len(encoded)
	}
	for len(s.ring) > s.opts.MaxCatchUpEvents || s.ringBytes > s.opts.MaxCatchUpBytes {
		encoded, _ := json.Marshal(s.ring[0])
		s.ringBytes -= len(encoded)
		s.ring = s.ring[1:]
	}
}

// logNeedsHeaderRedactionLocked scans the complete active append log so a
// plaintext value in evicted history cannot survive merely because it aged
// out of the retained state and bounded SSE ring. The lightweight decode skips
// payload bodies while preserving the store's per-record size bound.
func (s *Store) logNeedsHeaderRedactionLocked(sensitive func(string) bool) (bool, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	if s.f == nil {
		return false, os.ErrClosed
	}
	info, err := s.f.Stat()
	if err != nil {
		return false, err
	}
	reader := bufio.NewReaderSize(io.NewSectionReader(s.f, 0, info.Size()), 64<<10)
	var offset int64
	for {
		line, complete, err := readRecord(reader)
		if err != nil {
			return false, fmt.Errorf("read store at byte %d: %w", offset, err)
		}
		if !complete {
			return false, nil
		}
		var metadata struct {
			Request *struct {
				Headers Header
			} `json:"request"`
			Attempt *struct {
				ResponseHeaders Header
			} `json:"attempt"`
		}
		if err := json.Unmarshal(line, &metadata); err != nil {
			return false, fmt.Errorf("decode store at byte %d: %w", offset, err)
		}
		if metadata.Request != nil && headerValuesNeedRedaction(metadata.Request.Headers, sensitive) ||
			metadata.Attempt != nil && headerValuesNeedRedaction(metadata.Attempt.ResponseHeaders, sensitive) {
			return true, nil
		}
		offset += int64(len(line))
	}
}

func headerValuesNeedRedaction(headers Header, sensitive func(string) bool) bool {
	for name, values := range headers {
		if sensitive(name) && (len(values) != 1 || values[0] != "[REDACTED]") {
			return true
		}
	}
	return false
}

func readEventAt(f *os.File, ref recordRef) (Event, error) {
	if f == nil || ref.offset < 0 || ref.length <= 0 || ref.length > maxEventBytes {
		return Event{}, errors.New("invalid store record reference")
	}
	data := make([]byte, ref.length)
	n, err := f.ReadAt(data, ref.offset)
	if err != nil && !(errors.Is(err, io.EOF) && n == len(data)) {
		return Event{}, err
	}
	if n != len(data) {
		return Event{}, io.ErrUnexpectedEOF
	}
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return Event{}, err
	}
	if event.Seq != ref.seq {
		return Event{}, errors.New("store record sequence changed")
	}
	return event, nil
}

func (s *Store) poison(err error) {
	s.mu.Lock()
	if s.health == nil {
		s.health = err
	}
	s.mu.Unlock()
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
			summary: RequestSummary{ID: r.ID, DeliveryID: r.DeliveryID, Method: r.Method, Path: r.Path, BodySHA256: r.BodySHA256, ReceivedAt: r.ReceivedAt, BodyBytes: s.requestBytes[id]},
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
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	records := s.snapshotRecordsLocked()
	if uint64(len(records)) > ^uint64(0)-s.seq {
		return errors.New("store sequence exhausted during compaction")
	}
	// Snapshot records are new durable records, not a rewriting of a
	// one-record-per-object history. Assign them fresh sequence numbers after
	// the last published event. This remains monotonic even when one atomic
	// event originally carried both a request and its forwarding job.
	previousSeq := s.seq
	start := s.seq
	if len(records) > 0 {
		start++
	}
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
	newRequestRecord := make(map[string]recordRef, len(s.requestRecord))
	newAttemptRecord := make(map[string]recordRef, len(s.attemptRecord))
	var offset int64
	for i := range records {
		event, err := s.hydrateSnapshotEventLocked(records[i])
		if err != nil {
			cleanup()
			return err
		}
		event.Seq = start + uint64(i)
		event.Snapshot = true
		encoded, err := json.Marshal(event)
		if err != nil {
			cleanup()
			return err
		}
		encoded = append(encoded, '\n')
		if _, err := w.Write(encoded); err != nil {
			cleanup()
			return err
		}
		ref := recordRef{offset: offset, length: len(encoded), seq: event.Seq}
		if event.Request != nil {
			newRequestRecord[event.Request.ID] = ref
		}
		if event.Attempt != nil {
			newAttemptRecord[event.Attempt.ID] = ref
		}
		offset += int64(len(encoded))
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
	old := s.f
	oldClosed := false
	if runtime.GOOS == "windows" {
		// MoveFileEx cannot replace an existing destination while Relaybox's
		// own destination handle remains open. The record and replacement are
		// both synced by this point, so close only for the atomic path swap.
		if err := old.Close(); err != nil {
			os.Remove(tmpName)
			return err
		}
		oldClosed = true
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		if oldClosed {
			reopened, reopenErr := openStoreFile(s.path, false)
			if reopenErr != nil {
				return errors.Join(err, fmt.Errorf("reopen store after failed compaction: %w", reopenErr))
			}
			if _, seekErr := reopened.Seek(0, io.SeekEnd); seekErr != nil {
				reopened.Close()
				return errors.Join(err, fmt.Errorf("seek reopened store after failed compaction: %w", seekErr))
			}
			s.f = reopened
		}
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
	s.f = newFile
	if len(records) > 0 {
		s.seq = start + uint64(len(records)) - 1
	} else {
		// An empty current-state snapshot still replaces historical disk data
		// (including evicted legacy secrets). Preserve the live cursor until a
		// future append even though there is no record to carry a new sequence.
		s.seq = previousSeq
	}
	// eventCount measures mutations since the last compaction. The compacted
	// snapshot itself can legitimately contain more records than MaxEvents
	// when atomic events expand into separate current-state records; counting
	// those would otherwise trigger compaction on every subsequent append.
	s.eventCount = 0
	s.requestRecord = newRequestRecord
	s.attemptRecord = newAttemptRecord
	if oldClosed {
		return nil
	}
	return old.Close()
}

func (s *Store) hydrateSnapshotEventLocked(event Event) (Event, error) {
	event = cloneEvent(event)
	if event.Request != nil {
		stored, err := readEventAt(s.f, s.requestRecord[event.Request.ID])
		if err != nil {
			return Event{}, fmt.Errorf("read request %q for compaction: %w", event.Request.ID, err)
		}
		if stored.Request == nil || stored.Request.ID != event.Request.ID {
			return Event{}, fmt.Errorf("read request %q for compaction: store record identity changed", event.Request.ID)
		}
		event.Request.Body = append([]byte(nil), stored.Request.Body...)
		if err := validateRequestDigest(*event.Request); err != nil {
			return Event{}, fmt.Errorf("read request %q for compaction: %w", event.Request.ID, err)
		}
	}
	if event.Attempt != nil {
		stored, err := readEventAt(s.f, s.attemptRecord[event.Attempt.ID])
		if err != nil {
			return Event{}, fmt.Errorf("read attempt %q for compaction: %w", event.Attempt.ID, err)
		}
		if stored.Attempt == nil || stored.Attempt.ID != event.Attempt.ID {
			return Event{}, fmt.Errorf("read attempt %q for compaction: store record identity changed", event.Attempt.ID)
		}
		event.Attempt.ResponseBody = append([]byte(nil), stored.Attempt.ResponseBody...)
	}
	return event, nil
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
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.f.Close()
}
