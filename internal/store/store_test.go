package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	var wg sync.WaitGroup
	counts := make(chan CaptureResult, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, r, e := s.Capture(Request{ID: time.Now().String(), DeliveryID: "same", BodySHA256: "hash"})
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
	r := Request{ID: "r"}
	s.Capture(r)
	a := Attempt{ID: "a", RequestID: "r", Status: 200, ResponseBody: []byte("ok")}
	s.Append(Event{Kind: "attempt.finished", Attempt: &a})
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
	r := Request{ID: "1", BodySHA256: "a"}
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
	r.BodySHA256 = "b"
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
