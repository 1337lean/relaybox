package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStoreRecoveryAtomicDedupAndConflict(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.ndjson")
	s, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	body := []byte("body")
	sum := sha256.Sum256(body)
	r := Request{ID: "1", DeliveryID: "d", BodySHA256: hex.EncodeToString(sum[:]), Body: body, ReceivedAt: time.Now()}
	if _, got, e := s.Capture(r); e != nil || got != Captured {
		t.Fatalf("%v %v", got, e)
	}
	r.ID = "2"
	if id, got, e := s.Capture(r); e != nil || got != Duplicate || id != "1" {
		t.Fatalf("%q %v %v", id, got, e)
	}
	r.BodySHA256 = "different"
	if _, got, _ := s.Capture(r); got != Conflict {
		t.Fatalf("want conflict, got %v", got)
	}
	s.Close()
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("broken")
	f.Close()
	s, e = Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, _, ok := s.Get("1"); !ok {
		t.Fatal("request not recovered")
	}
}

func TestRecoveryDiscardsUnterminatedRecord(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.ndjson")
	if err := os.WriteFile(p, []byte(`{"seq":1,"kind":"request.received"}`), 0600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("unterminated record was retained (%d bytes)", info.Size())
	}
}

func TestRecoveryRejectsSequenceGaps(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.ndjson")
	data := []byte("{\"seq\":2,\"kind\":\"request.received\"}\n")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(p); err == nil {
		s.Close()
		t.Fatal("store with a sequence gap was accepted")
	}
}
func TestConcurrentCaptureIsAtomic(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "s"))
	defer s.Close()
	body := []byte("body")
	sum := sha256.Sum256(body)
	var wg sync.WaitGroup
	counts := make(chan CaptureResult, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, r, e := s.Capture(Request{ID: time.Now().String(), DeliveryID: "same", BodySHA256: hex.EncodeToString(sum[:]), Body: body})
			if e != nil {
				t.Error(e)
			}
			counts <- r
		}()
	}
	wg.Wait()
	close(counts)
	captured := 0
	for r := range counts {
		if r == Captured {
			captured++
		}
	}
	if captured != 1 {
		t.Fatalf("captured %d", captured)
	}
}
func TestAttemptImmutable(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "s"))
	defer s.Close()
	body := []byte("body")
	sum := sha256.Sum256(body)
	r := Request{ID: "r", BodySHA256: hex.EncodeToString(sum[:]), Body: body}
	j := Job{ID: "j", RequestID: r.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: time.Now().UTC()}
	if _, _, _, err := s.Accept(r, &j); err != nil {
		t.Fatal(err)
	}
	a := Attempt{ID: "a", JobID: "j", RequestID: "r", Number: 1, Status: 200, ResponseBody: []byte("ok")}
	if _, err := s.Append(Event{Kind: "attempt.finished", Attempt: &a}); err != nil {
		t.Fatal(err)
	}
	a.Status = 500
	a.ResponseBody[0] = 'x'
	_, got, _ := s.Get("r")
	if got[0].Status != 200 || string(got[0].ResponseBody) != "ok" {
		t.Fatal("mutation leaked")
	}
}
func TestSubscriptionSnapshot(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "s"))
	defer s.Close()
	body := []byte("a")
	sum := sha256.Sum256(body)
	r := Request{ID: "1", BodySHA256: hex.EncodeToString(sum[:]), Body: body}
	s.Capture(r)
	old, ch, cancel, e := s.SubscribeFrom(0)
	if e != nil {
		t.Fatal(e)
	}
	defer cancel()
	if len(old) != 1 {
		t.Fatalf("old %d", len(old))
	}
	r.ID = "2"
	r.Body = []byte("b")
	sum = sha256.Sum256(r.Body)
	r.BodySHA256 = hex.EncodeToString(sum[:])
	s.Capture(r)
	select {
	case e := <-ch:
		if e.Request.ID != "2" {
			t.Fatal(e.Request.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("no live event")
	}
}

func TestSubscriptionReadsOpenedStoreNotReplacementPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.ndjson")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	body := []byte("body")
	sum := sha256.Sum256(body)
	if _, _, err := s.Capture(Request{ID: "original", BodySHA256: hex.EncodeToString(sum[:]), Body: body}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("attacker-controlled replacement\n"), 0600); err != nil {
		t.Fatal(err)
	}

	old, _, cancel, err := s.SubscribeFrom(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if len(old) != 1 || old[0].Request == nil || old[0].Request.ID != "original" {
		t.Fatalf("snapshot = %#v", old)
	}
}

func TestSubscriptionCatchUpIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.ndjson")
	var contents bytes.Buffer
	bodyHash := sha256.Sum256(nil)
	encoder := json.NewEncoder(&contents)
	for i := 1; i <= maxCatchUpEvents+1; i++ {
		event := Event{
			Seq:  uint64(i),
			Kind: "request.received",
			At:   time.Now().UTC(),
			Request: &Request{
				ID:         fmt.Sprintf("request-%d", i),
				BodySHA256: hex.EncodeToString(bodyHash[:]),
			},
		}
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, contents.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Sequence() != maxCatchUpEvents+1 {
		t.Fatalf("sequence = %d", s.Sequence())
	}
	if _, _, _, err := s.SubscribeFrom(0); !errors.Is(err, ErrEventBacklog) {
		t.Fatalf("catch-up error = %v", err)
	}
}
func FuzzRecovery(f *testing.F) {
	f.Add([]byte("{}\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "s")
		os.WriteFile(p, b, 0600)
		s, _ := Open(p)
		if s != nil {
			s.Close()
		}
	})
}

func validRequest(id, deliveryID, body string, receivedAt time.Time) Request {
	payload := []byte(body)
	sum := sha256.Sum256(payload)
	return Request{ID: id, DeliveryID: deliveryID, BodySHA256: hex.EncodeToString(sum[:]), Body: payload, ReceivedAt: receivedAt}
}

func TestAcceptPersistsCaptureAndIntentInOneRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.ndjson")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r := validRequest("request-1", "delivery-1", "body", now)
	j := Job{ID: "job-1", RequestID: r.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: now}
	id, result, persisted, err := s.Accept(r, &j)
	if err != nil || result != Captured || id != r.ID || persisted == nil || persisted.ID != j.ID {
		t.Fatalf("accept = %q %v %#v %v", id, result, persisted, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines := bytes.Count(contents, []byte{'\n'}); lines != 1 {
		t.Fatalf("capture and intent used %d records", lines)
	}
	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(contents), &event); err != nil {
		t.Fatal(err)
	}
	if event.Kind != "capture.accepted" || event.Request == nil || event.Job == nil {
		t.Fatalf("atomic event = %#v", event)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, ok := s.Get(r.ID); !ok || s.JobCounts()["pending"] != 1 {
		t.Fatalf("recovered request/job = %v %#v", ok, s.JobCounts())
	}
}

func TestDuplicateKeepsOriginalIntentDiscoverable(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "store.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	r := validRequest("request-1", "delivery-1", "body", now)
	j := Job{ID: "job-1", RequestID: r.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: now}
	if _, _, _, err := s.Accept(r, &j); err != nil {
		t.Fatal(err)
	}
	duplicate := r
	duplicate.ID = "request-2"
	newJob := Job{ID: "job-2", RequestID: duplicate.ID, URL: j.URL, State: "pending", CreatedAt: now.Add(time.Second)}
	id, result, existing, err := s.Accept(duplicate, &newJob)
	if err != nil || result != Duplicate || id != r.ID || existing == nil || existing.ID != j.ID {
		t.Fatalf("duplicate = %q %v %#v %v", id, result, existing, err)
	}
	if counts := s.JobCounts(); counts["pending"] != 1 {
		t.Fatalf("job counts = %#v", counts)
	}
}

func TestDuplicateRepairsMissingLegacyForwardIntent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.ndjson")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	original := validRequest("request-1", "delivery-1", "body", now)
	if _, result, err := s.Capture(original); err != nil || result != Captured {
		t.Fatalf("legacy capture = %v %v", result, err)
	}
	duplicate := original
	duplicate.ID = "request-2"
	intent := Job{ID: "job-1", RequestID: duplicate.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: now.Add(time.Second)}
	id, result, repaired, err := s.Accept(duplicate, &intent)
	if err != nil || result != Duplicate || id != original.ID || repaired == nil {
		t.Fatalf("repair = %q %v %#v %v", id, result, repaired, err)
	}
	if repaired.RequestID != original.ID || repaired.ID != intent.ID || s.JobCounts()["pending"] != 1 {
		t.Fatalf("repaired intent = %#v, counts = %#v", repaired, s.JobCounts())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	unfinished := s.UnfinishedJobs()
	if len(unfinished) != 1 || unfinished[0].RequestID != original.ID {
		t.Fatalf("recovered repaired intent = %#v", unfinished)
	}
}

func TestGeneratedRequestAndJobIDsCannotOverwriteState(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "store.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	first := validRequest("request-1", "delivery-1", "body-1", now)
	firstJob := Job{ID: "job-1", RequestID: first.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: now}
	if _, _, _, err := s.Accept(first, &firstJob); err != nil {
		t.Fatal(err)
	}
	requestCollision := validRequest("request-1", "delivery-2", "body-2", now.Add(time.Second))
	if _, _, _, err := s.Accept(requestCollision, nil); !errors.Is(err, ErrIDCollision) {
		t.Fatalf("request collision error = %v", err)
	}
	second := validRequest("request-2", "delivery-2", "body-2", now.Add(time.Second))
	jobCollision := Job{ID: "job-1", RequestID: second.ID, URL: firstJob.URL, State: "pending", CreatedAt: now.Add(time.Second)}
	if _, _, _, err := s.Accept(second, &jobCollision); !errors.Is(err, ErrIDCollision) {
		t.Fatalf("job collision error = %v", err)
	}
	stored, _, ok := s.Get(first.ID)
	if !ok || string(stored.Body) != "body-1" {
		t.Fatalf("original request changed: %#v", stored)
	}
}

func TestLeaseOwnershipRetryAndCompletionAreAtomic(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "store.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	r := validRequest("request-1", "delivery-1", "body", now)
	j := Job{ID: "job-1", RequestID: r.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: now}
	if _, _, _, err := s.Accept(r, &j); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := s.ClaimNextJob("worker-1", now, time.Minute)
	if err != nil || !ok || claimed.LeaseOwner != "worker-1" {
		t.Fatalf("claim = %#v %v %v", claimed, ok, err)
	}
	if _, ok, err := s.ClaimNextJob("worker-2", now.Add(time.Second), time.Minute); err != nil || ok {
		t.Fatalf("competing claim = %v %v", ok, err)
	}
	attempt := Attempt{ID: "attempt-1", JobID: j.ID, RequestID: r.ID, Number: 1, StartedAt: now, FinishedAt: now.Add(time.Second)}
	if err := s.RecordAttempt(j.ID, "worker-2", attempt, "retrying", "", now.Add(time.Minute)); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("non-owner transition = %v", err)
	}
	if err := s.RecordAttempt(j.ID, "worker-1", attempt, "retrying", "", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ClaimNextJob("worker-2", now.Add(30*time.Second), time.Minute); ok {
		t.Fatal("job claimed before retry availability")
	}
	claimed, ok, err = s.ClaimNextJob("worker-2", now.Add(2*time.Minute), time.Minute)
	if err != nil || !ok {
		t.Fatalf("retry claim = %#v %v %v", claimed, ok, err)
	}
	attempt.ID = "attempt-2"
	attempt.Number = 2
	attempt.StartedAt = now.Add(2 * time.Minute)
	attempt.FinishedAt = attempt.StartedAt.Add(time.Second)
	if err := s.RecordAttempt(j.ID, "worker-2", attempt, "succeeded", "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if counts := s.JobCounts(); counts["succeeded"] != 1 || len(s.UnfinishedJobs()) != 0 {
		t.Fatalf("final state = %#v", counts)
	}
}

func TestRetentionEvictionCompactionAndRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.ndjson")
	s, err := OpenWithOptions(path, Options{MaxCaptures: 2, MaxEvents: 2})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 1; i <= 3; i++ {
		r := validRequest(fmt.Sprintf("request-%d", i), fmt.Sprintf("delivery-%d", i), fmt.Sprintf("body-%d", i), now.Add(time.Duration(i)*time.Second))
		if _, result, err := s.Capture(r); err != nil || result != Captured {
			t.Fatalf("capture %d = %v %v", i, result, err)
		}
	}
	if _, _, ok := s.Get("request-1"); ok {
		t.Fatal("oldest completed capture was not evicted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenWithOptions(path, Options{MaxCaptures: 2, MaxEvents: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, ok := s.Get("request-1"); ok {
		t.Fatal("evicted capture returned after recovery")
	}
	for _, id := range []string{"request-2", "request-3"} {
		if _, _, ok := s.Get(id); !ok {
			t.Fatalf("retained capture %s missing", id)
		}
	}
}

func TestCompactionSequenceHandlesAtomicEventExpansion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.ndjson")
	const captures = 101
	s, err := OpenWithOptions(path, Options{MaxCaptures: 200, MaxEvents: 100})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < captures; i++ {
		request := validRequest(fmt.Sprintf("request-%03d", i), fmt.Sprintf("delivery-%03d", i), fmt.Sprintf("body-%03d", i), now.Add(time.Duration(i)*time.Second))
		job := Job{ID: fmt.Sprintf("job-%03d", i), RequestID: request.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: request.ReceivedAt}
		if _, result, _, err := s.Accept(request, &job); err != nil || result != Captured {
			t.Fatalf("capture %d = %v %v", i, result, err)
		}
	}
	// The first 101 events expand to 202 current-state snapshot records. Their
	// fresh sequence range must follow 101 rather than underflow uint64.
	if got := s.Sequence(); got != 303 {
		t.Fatalf("post-compaction sequence = %d, want 303", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenWithOptions(path, Options{MaxCaptures: 200, MaxEvents: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.UnfinishedJobs()) != captures {
		t.Fatalf("recovered jobs = %d", len(s.UnfinishedJobs()))
	}
	request, _, ok, err := s.Load("request-100")
	if err != nil || !ok || string(request.Body) != "body-100" {
		t.Fatalf("recovered payload = %#v %v %v", request, ok, err)
	}
	request = validRequest("request-101", "delivery-101", "body-101", now.Add(captures*time.Second))
	job := Job{ID: "job-101", RequestID: request.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: request.ReceivedAt}
	if _, result, _, err := s.Accept(request, &job); err != nil || result != Captured {
		t.Fatalf("post-recovery capture = %v %v", result, err)
	}
	// Recovered snapshot records do not count as mutations. The first append
	// after reopening must not immediately rewrite the 202-record snapshot.
	if got := s.Sequence(); got != 304 {
		t.Fatalf("post-recovery append sequence = %d, want 304", got)
	}
}

func TestPayloadBodiesAreLoadedFromRecordOffsets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.ndjson")
	s, err := OpenWithOptions(path, Options{MaxEvents: 2})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := validRequest("request-1", "delivery-1", "request payload", now)
	job := Job{ID: "job-1", RequestID: request.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: now}
	if _, _, _, err := s.Accept(request, &job); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := s.ClaimNextJob("worker", now, time.Minute)
	if err != nil || !ok {
		t.Fatalf("claim = %#v %v %v", claimed, ok, err)
	}
	attempt := Attempt{ID: "attempt-1", JobID: job.ID, RequestID: request.ID, Number: 1, StartedAt: now, FinishedAt: now.Add(time.Second), ResponseBody: []byte("response payload")}
	if err := s.RecordAttempt(job.ID, "worker", attempt, "succeeded", "", time.Time{}); err != nil {
		t.Fatal(err)
	}

	s.mu.RLock()
	residentRequestBytes := len(s.requests[request.ID].Body)
	residentAttemptBytes := len(s.attempts[request.ID][0].ResponseBody)
	s.mu.RUnlock()
	if residentRequestBytes != 0 || residentAttemptBytes != 0 {
		t.Fatalf("resident payload bytes = request %d, attempt %d", residentRequestBytes, residentAttemptBytes)
	}
	loaded, attempts, ok, err := s.Load(request.ID)
	if err != nil || !ok || string(loaded.Body) != "request payload" || len(attempts) != 1 || string(attempts[0].ResponseBody) != "response payload" {
		t.Fatalf("loaded = %#v, attempts = %#v, ok = %v, err = %v", loaded, attempts, ok, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = OpenWithOptions(path, Options{MaxEvents: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	loaded, attempts, ok, err = s.Load(request.ID)
	if err != nil || !ok || string(loaded.Body) != "request payload" || len(attempts) != 1 || string(attempts[0].ResponseBody) != "response payload" {
		t.Fatalf("recovered load = %#v, attempts = %#v, ok = %v, err = %v", loaded, attempts, ok, err)
	}
}

func TestRedactHeadersRecountsAndTrimsCatchUpRing(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "store.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	request := validRequest("request-1", "delivery-1", "body", time.Now().UTC())
	request.Headers = Header{"X-ApiKey": {"x"}}
	if _, result, err := s.Capture(request); err != nil || result != Captured {
		t.Fatalf("capture = %v %v", result, err)
	}

	s.mu.Lock()
	if len(s.ring) != 1 {
		t.Fatalf("initial ring length = %d", len(s.ring))
	}
	s.opts.MaxCatchUpBytes = s.ringBytes + 1
	s.mu.Unlock()
	if err := s.RedactHeaders(func(name string) bool { return strings.EqualFold(name, "X-ApiKey") }); err != nil {
		t.Fatal(err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.ring) != 0 || s.ringBytes != 0 {
		t.Fatalf("redacted ring length/bytes = %d/%d, want 0/0", len(s.ring), s.ringBytes)
	}
}

func TestRedactHeadersPurgesHistoricalLogWithEmptyCurrentState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.ndjson")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const canary = "historical-only-secret"
	request := validRequest("request-1", "delivery-1", "body", time.Now().UTC())
	request.Headers = Header{"X-ApiKey": {canary}}
	if _, result, err := s.Capture(request); err != nil || result != Captured {
		t.Fatalf("capture = %v %v", result, err)
	}
	wantSequence := s.Sequence()

	// Model an entirely evicted current state whose old event has also aged out
	// of the catch-up ring. RedactHeaders must still purge the active log based
	// on its complete-file scan.
	s.mu.Lock()
	s.removeRequest(request.ID)
	s.ring = nil
	s.ringBytes = 0
	s.mu.Unlock()
	if err := s.RedactHeaders(func(name string) bool { return strings.EqualFold(name, "X-ApiKey") }); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != 0 || bytes.Contains(contents, []byte(canary)) {
		t.Fatalf("empty-state compacted log = %q", contents)
	}
	if got := s.Sequence(); got != wantSequence {
		t.Fatalf("sequence after empty compaction = %d, want %d", got, wantSequence)
	}
}

func TestConcurrentLoadsAndCompaction(t *testing.T) {
	s, err := OpenWithOptions(filepath.Join(t.TempDir(), "store.ndjson"), Options{MaxCaptures: 100, MaxEvents: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	anchor := validRequest("anchor", "anchor-delivery", strings.Repeat("payload", 1024), now)
	anchorJob := Job{ID: "anchor-job", RequestID: anchor.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: now}
	if _, _, _, err := s.Accept(anchor, &anchorJob); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errCh := make(chan error, 4)
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for j := 0; j < 50; j++ {
				loaded, _, ok, err := s.Load(anchor.ID)
				if err != nil || !ok || !bytes.Equal(loaded.Body, anchor.Body) {
					errCh <- fmt.Errorf("load %d: ok=%v err=%v bytes=%d", j, ok, err, len(loaded.Body))
					return
				}
			}
		}()
	}
	close(start)
	for i := 0; i < 30; i++ {
		request := validRequest(fmt.Sprintf("request-%d", i), fmt.Sprintf("delivery-%d", i), fmt.Sprintf("body-%d", i), now.Add(time.Duration(i+1)*time.Second))
		if _, _, err := s.Capture(request); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestRetentionDoesNotEvictUnfinishedForwarding(t *testing.T) {
	s, err := OpenWithOptions(filepath.Join(t.TempDir(), "store.ndjson"), Options{MaxCaptures: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	r := validRequest("request-1", "delivery-1", "body", now)
	j := Job{ID: "job-1", RequestID: r.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: now}
	if _, _, _, err := s.Accept(r, &j); err != nil {
		t.Fatal(err)
	}
	second := validRequest("request-2", "delivery-2", "body-2", now.Add(time.Second))
	if _, _, err := s.Capture(second); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if _, _, ok := s.Get(r.ID); !ok {
		t.Fatal("unfinished capture was evicted")
	}
}

func TestSearchIndexAndSSECatchUpAreBounded(t *testing.T) {
	s, err := OpenWithOptions(filepath.Join(t.TempDir(), "store.ndjson"), Options{MaxSearchBytes: 4, MaxCatchUpEvents: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	for i, body := range []string{"abcdef", "second", "third"} {
		r := validRequest(fmt.Sprintf("request-%d", i+1), fmt.Sprintf("delivery-%d", i+1), body, now.Add(time.Duration(i)*time.Second))
		if _, _, err := s.Capture(r); err != nil {
			t.Fatal(err)
		}
	}
	if items, total := s.ListSummaries("abcd", 0, 10); total != 1 || len(items) != 1 {
		t.Fatalf("indexed prefix result = %d %#v", total, items)
	}
	if _, total := s.ListSummaries("ef", 0, 10); total != 0 {
		t.Fatalf("unindexed suffix matched %d records", total)
	}
	if _, _, _, err := s.SubscribeFrom(0); !errors.Is(err, ErrEventBacklog) {
		t.Fatalf("old cursor error = %v", err)
	}
	old, _, cancel, err := s.SubscribeFrom(1)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if len(old) != 2 || old[0].Seq != 2 || old[1].Seq != 3 {
		t.Fatalf("bounded ring catch-up = %#v", old)
	}
}

func TestAtomicCaptureFailureInjection(t *testing.T) {
	now := time.Now().UTC()
	r := validRequest("request-1", "delivery-1", "body", now)
	j := Job{ID: "job-1", RequestID: r.ID, URL: "https://example.com/hooks", State: "pending", CreatedAt: now}

	writePath := filepath.Join(t.TempDir(), "write.ndjson")
	s, err := Open(writePath)
	if err != nil {
		t.Fatal(err)
	}
	s.beforeWrite = func(Event) error { return errors.New("injected write failure") }
	if _, _, _, err := s.Accept(r, &j); err == nil {
		t.Fatal("injected write failure was ignored")
	}
	if _, _, ok := s.Get(r.ID); ok {
		t.Fatal("failed write entered the in-memory index")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(writePath); err != nil || info.Size() != 0 {
		t.Fatalf("failed write size = %v, %v", info, err)
	}

	syncPath := filepath.Join(t.TempDir(), "sync.ndjson")
	s, err = Open(syncPath)
	if err != nil {
		t.Fatal(err)
	}
	s.beforeSync = func(Event) error { return errors.New("injected sync failure") }
	if _, _, _, err := s.Accept(r, &j); err == nil {
		t.Fatal("injected sync failure was ignored")
	}
	if _, _, ok := s.Get(r.ID); ok {
		t.Fatal("failed sync entered the in-memory index")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(syncPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, ok := s.Get(r.ID); !ok || s.JobCounts()["pending"] != 1 {
		t.Fatalf("ambiguous sync recovery lost atomic record: request=%v jobs=%#v", ok, s.JobCounts())
	}
}

func TestCanceledSearchAndSlowSubscriberAreBounded(t *testing.T) {
	s, err := OpenWithOptions(filepath.Join(t.TempDir(), "store.ndjson"), Options{SubscriberBacklog: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	ctx, cancelSearch := context.WithCancel(context.Background())
	cancelSearch()
	if _, _, _, err := s.ListSummariesContext(ctx, "anything", 0, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled search error = %v", err)
	}

	_, ch, cancelSubscription, err := s.SubscribeFrom(s.Sequence())
	if err != nil {
		t.Fatal(err)
	}
	defer cancelSubscription()
	for i := 1; i <= 2; i++ {
		r := validRequest(fmt.Sprintf("request-%d", i), fmt.Sprintf("delivery-%d", i), "body", now.Add(time.Duration(i)*time.Second))
		if _, _, err := s.Capture(r); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := <-ch; !ok {
		t.Fatal("buffered event missing")
	}
	if _, ok := <-ch; ok {
		t.Fatal("slow subscriber was not disconnected")
	}
}

func TestConcurrentWorstCaseSearchDoesNotBlockCapture(t *testing.T) {
	s, err := OpenWithOptions(filepath.Join(t.TempDir(), "store.ndjson"), Options{MaxCaptures: 600, MaxSearchBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	body := strings.Repeat("a", 64<<10)
	for i := 0; i < 500; i++ {
		r := validRequest(fmt.Sprintf("request-%d", i), fmt.Sprintf("delivery-%d", i), body, now.Add(time.Duration(i)*time.Nanosecond))
		if _, _, err := s.Capture(r); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 10; j++ {
				if _, _, _, err := s.ListSummariesContext(context.Background(), "not-present", 0, 200); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	close(start)
	begin := time.Now()
	r := validRequest("request-new", "delivery-new", "new", now.Add(time.Hour))
	if _, _, err := s.Capture(r); err != nil {
		t.Fatal(err)
	}
	latency := time.Since(begin)
	wg.Wait()
	if latency > 500*time.Millisecond {
		t.Fatalf("capture blocked by search for %v", latency)
	}
}
