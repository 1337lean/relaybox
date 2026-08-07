package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1337lean/relaybox/internal/store"
)

func testApp(t *testing.T, c Config) (*App, *store.Store) {
	t.Helper()
	s, e := store.Open(filepath.Join(t.TempDir(), "s"))
	if e != nil {
		t.Fatal(e)
	}
	c.Store = s
	if c.OperatorToken == "" {
		c.OperatorToken = "operator"
	}
	return New(c), s
}
func stopApp(t *testing.T, a *App, s *store.Store) {
	t.Helper()
	ctx, c := contextWithTimeout()
	defer c()
	if e := a.Shutdown(ctx); e != nil {
		t.Error(e)
	}
	s.Close()
}
func contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Second)
}
func TestIngestSignatureAtomicDedupConflictRedaction(t *testing.T) {
	a, s := testApp(t, Config{Secret: "key"})
	defer stopApp(t, a, s)
	body := "hello"
	m := hmac.New(sha256.New, []byte("key"))
	m.Write([]byte(body))
	sig := "sha256=" + hex.EncodeToString(m.Sum(nil))
	send := func(body string) int {
		r := httptest.NewRequest("POST", "/inbox", strings.NewReader(body))
		r.Header.Set("X-Hub-Signature-256", sig)
		r.Header.Set("Authorization", "bearer secret")
		r.Header.Set("X-GitHub-Delivery", "d1")
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if send(body) != 202 || send(body) != 200 {
		t.Fatal("dedup statuses")
	}
	if send("different") != 401 {
		t.Fatal("signature must be checked before conflict")
	}
	items, total := s.ListSummaries("", 0, 10)
	if total != 1 || len(items) != 1 {
		t.Fatal(total)
	}
	stored, _, ok := s.Get(items[0].ID)
	if !ok || !stored.SignatureVerified {
		t.Fatal("valid signature was not recorded as verified")
	}
}
func TestOperatorProtectionAndSession(t *testing.T) {
	a, s := testApp(t, Config{})
	defer stopApp(t, a, s)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/requests", nil))
	if w.Code != 401 {
		t.Fatalf("%d", w.Code)
	}
	r := httptest.NewRequest("POST", "/api/session", nil)
	r.Header.Set("Authorization", "Bearer operator")
	r.Header.Set("Origin", "http://evil.example")
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross origin %d", w.Code)
	}
	r = httptest.NewRequest("POST", "http://example.com/api/session", nil)
	r.Header.Set("Authorization", "Bearer operator")
	r.Header.Set("Origin", "http://example.com")
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 204 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("session %d", w.Code)
	}
}

func TestSecureCookieForTLSProxyMode(t *testing.T) {
	a, s := testApp(t, Config{SecureCookies: true})
	defer stopApp(t, a, s)

	request := httptest.NewRequest("POST", "http://example.com/api/session", nil)
	request.Header.Set("Authorization", "Bearer operator")
	request.Header.Set("Origin", "https://example.com")
	response := httptest.NewRecorder()
	a.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("session response = %d", response.Code)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure {
		t.Fatalf("secure cookie mode produced %#v", cookies)
	}
}

func TestOperatorRejectsCrossSchemeOrigin(t *testing.T) {
	a, s := testApp(t, Config{})
	defer stopApp(t, a, s)

	request := httptest.NewRequest("POST", "http://example.com/api/session", nil)
	request.Header.Set("Authorization", "Bearer operator")
	request.Header.Set("Origin", "https://example.com")
	response := httptest.NewRecorder()
	a.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-scheme response = %d", response.Code)
	}
}

func TestOperatorCookieRequiresOriginForMutation(t *testing.T) {
	a, s := testApp(t, Config{})
	defer stopApp(t, a, s)

	request := httptest.NewRequest("POST", "http://example.com/api/session", nil)
	request.AddCookie(&http.Cookie{Name: "relaybox_operator", Value: sessionToken("operator")})
	response := httptest.NewRecorder()
	a.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("originless cookie request = %d", response.Code)
	}
}
func TestListSummaryNoBody(t *testing.T) {
	a, s := testApp(t, Config{})
	defer stopApp(t, a, s)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/inbox", strings.NewReader("secret-body")))
	r := httptest.NewRequest("GET", "/api/requests", nil)
	r.Header.Set("Authorization", "Bearer operator")
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "secret-body") {
		t.Fatal("list leaked body")
	}
	var page struct{ Total int }
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Total != 1 {
		t.Fatal(w.Body.String())
	}
	items, _ := s.ListSummaries("", 0, 10)
	stored, _, ok := s.Get(items[0].ID)
	if !ok || stored.SignatureVerified {
		t.Fatal("an unsigned request was reported as signature-verified")
	}
}
func TestForwardRetryAfterZeroAndNoRedirect(t *testing.T) {
	n := 0
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer dst.Close()
	a, s := testApp(t, Config{ForwardURL: dst.URL, Attempts: 3, AllowPrivateTargets: true, BaseBackoff: time.Second})
	defer stopApp(t, a, s)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/inbox", strings.NewReader("x")))
	if w.Code != 202 {
		t.Fatal(w.Code)
	}
	a.Wait()
	items, _ := s.ListSummaries("", 0, 10)
	_, at, _ := s.Get(items[0].ID)
	if len(at) != 2 || at[1].Status != 204 {
		t.Fatalf("%+v", at)
	}
}

func TestForwardingDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer redirectTarget.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, redirectTarget.URL, http.StatusFound)
	}))
	defer redirector.Close()
	a, s := testApp(t, Config{ForwardURL: redirector.URL, AllowPrivateTargets: true, PollInterval: 5 * time.Millisecond})
	defer stopApp(t, a, s)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/inbox", strings.NewReader("body")))
	if w.Code != http.StatusAccepted {
		t.Fatalf("capture response = %d", w.Code)
	}
	a.Wait()
	if redirected.Load() != 0 || s.JobCounts()["fatal"] != 1 {
		t.Fatalf("redirect calls = %d, jobs = %#v", redirected.Load(), s.JobCounts())
	}
}
func TestPrivateTargetValidation(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1:9",
		"http://[::ffff:127.0.0.1]:9",
		"http://100.64.0.1:9",
		"http://198.18.0.1:9",
		"http://255.255.255.255:9",
		"http://[64:ff9b::7f00:1]:9",
		"http://[2002:7f00:1::1]:9",
	} {
		if ValidateForwardTarget(target, false) == nil {
			t.Errorf("non-public literal %q was accepted", target)
		}
	}
	if ValidateForwardTarget("http://127.0.0.1:9", true) != nil {
		t.Fatal("development opt-in should permit private literal")
	}
}

func TestSecureClientDoesNotUseEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.example:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy.example:8080")

	client := secureClient(false)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("secure forwarding client inherited a proxy function")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion == 0 {
		t.Fatal("forwarding client has no minimum TLS version")
	}
	if transport.MaxResponseHeaderBytes <= 0 {
		t.Fatal("forwarding client has no response-header limit")
	}
}

func TestForwardHeadersDropSpoofingAndHopByHopValues(t *testing.T) {
	headers := forwardHeaders(store.Header{
		"Connection":            {"X-Remove, keep-alive"},
		"Keep-Alive":            {"timeout=5"},
		"X-Forwarded-For":       {"127.0.0.1"},
		"X-Real-IP":             {"127.0.0.1"},
		"X-Relaybox-Job-ID":     {"spoofed"},
		"X-Relaybox-Request-ID": {"spoofed"},
		"X-Remove":              {"remove me"},
		"X-Safe":                {"keep me"},
	})

	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Relaybox-Job-ID",
		"X-Relaybox-Request-ID",
		"X-Remove",
	} {
		if value := headers.Get(name); value != "" {
			t.Errorf("%s forwarded as %q", name, value)
		}
	}
	if got := headers.Get("X-Safe"); got != "keep me" {
		t.Fatalf("safe header = %q", got)
	}
}

type blockingReader struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (r *blockingReader) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return 0, io.EOF
}

func TestIngestConcurrencyIsBounded(t *testing.T) {
	a, s := testApp(t, Config{MaxInFlight: 1})
	defer stopApp(t, a, s)

	body := &blockingReader{started: make(chan struct{}), release: make(chan struct{})}
	firstDone := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/inbox", body))
		firstDone <- w.Code
	}()
	<-body.started

	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/inbox", nil))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("second request = %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}

	close(body.release)
	if code := <-firstDone; code != http.StatusAccepted {
		t.Fatalf("first request = %d", code)
	}
}

func TestBrowserUIUsesStrictExternalAssetPolicy(t *testing.T) {
	a, s := testApp(t, Config{})
	defer stopApp(t, a, s)

	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	policy := w.Header().Get("Content-Security-Policy")
	if strings.Contains(policy, "unsafe-inline") || !strings.Contains(policy, "default-src 'none'") {
		t.Fatalf("weak content security policy %q", policy)
	}
	if strings.Contains(w.Body.String(), "<script>") || !strings.Contains(w.Body.String(), `src="/app.js"`) {
		t.Fatal("UI did not load JavaScript as an external asset")
	}
}

func TestEventsRejectInvalidCursor(t *testing.T) {
	a, s := testApp(t, Config{})
	defer stopApp(t, a, s)

	request := httptest.NewRequest("GET", "/api/events?cursor=not-a-number", nil)
	request.Header.Set("Authorization", "Bearer operator")
	response := httptest.NewRecorder()
	a.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid cursor response = %d", response.Code)
	}
}
func TestRetryClassificationAndParse(t *testing.T) {
	if retryStatus(400) || !retryStatus(429) || !retryStatus(503) {
		t.Fatal("classification")
	}
	if d, ok := parseRetry("0", time.Now()); !ok || d != 0 {
		t.Fatalf("%v %v", d, ok)
	}
	if d, ok := parseRetry("9223372036854775807", time.Now()); !ok || d < 0 {
		t.Fatalf("overflowing Retry-After produced %v %v", d, ok)
	}
}
func FuzzVerify(f *testing.F) {
	f.Add("s", "sha256=00", []byte("x"))
	f.Fuzz(func(t *testing.T, s, sig string, b []byte) { verify(s, sig, b) })
}

func TestForwardIntentIDFailureCannotLeaveCaptureWithoutJob(t *testing.T) {
	var calls atomic.Int32
	idSource := func() (string, error) {
		if calls.Add(1) == 2 {
			return "", errors.New("entropy unavailable")
		}
		return "request-id", nil
	}
	a, s := testApp(t, Config{ForwardURL: "https://example.com/hooks", IDSource: idSource})
	defer stopApp(t, a, s)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/inbox", strings.NewReader("body")))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("response = %d", w.Code)
	}
	if _, total := s.ListSummaries("", 0, 10); total != 0 {
		t.Fatalf("entropy failure persisted %d captures", total)
	}
}

func TestLostWakeHintsDoNotStrandDurableJobs(t *testing.T) {
	var deliveries atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		deliveries.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	a, s := testApp(t, Config{
		ForwardURL:          destination.URL,
		AllowPrivateTargets: true,
		Concurrency:         4,
		QueueSize:           1,
		PollInterval:        5 * time.Millisecond,
	})
	defer stopApp(t, a, s)
	for i := 0; i < 24; i++ {
		r := httptest.NewRequest(http.MethodPost, "/inbox", strings.NewReader(fmt.Sprintf("body-%d", i)))
		r.Header.Set("X-GitHub-Delivery", fmt.Sprintf("delivery-%d", i))
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusAccepted {
			t.Fatalf("capture %d response = %d", i, w.Code)
		}
	}
	a.Wait()
	if got := deliveries.Load(); got != 24 {
		t.Fatalf("deliveries = %d", got)
	}
	if unfinished := s.UnfinishedJobs(); len(unfinished) != 0 {
		t.Fatalf("unfinished jobs = %#v", unfinished)
	}
}

func TestCanceledRequestAfterBodyDoesNotUndoDurableIntent(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	a, s := testApp(t, Config{ForwardURL: destination.URL, AllowPrivateTargets: true, PollInterval: 5 * time.Millisecond})
	defer stopApp(t, a, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodPost, "/inbox", strings.NewReader("body")).WithContext(ctx)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("response = %d", w.Code)
	}
	a.Wait()
	if counts := s.JobCounts(); counts["succeeded"] != 1 {
		t.Fatalf("job counts = %#v", counts)
	}
}

func TestRestartRecoversCommittedStaleLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.ndjson")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("body")
	sum := sha256.Sum256(body)
	now := time.Now().UTC()
	r := store.Request{ID: "request-1", DeliveryID: "delivery-1", BodySHA256: hex.EncodeToString(sum[:]), Body: body, ReceivedAt: now}
	destinationCalls := atomic.Int32{}
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	j := store.Job{ID: "job-1", RequestID: r.ID, URL: destination.URL, State: "pending", CreatedAt: now}
	if _, _, _, err := s.Accept(r, &j); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.ClaimNextJob("crashed-process", now, time.Hour); err != nil || !ok {
		t.Fatalf("prepare stale lease = %v %v", ok, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	a := New(Config{Store: s, OperatorToken: "operator", AllowPrivateTargets: true, PollInterval: 5 * time.Millisecond})
	defer stopApp(t, a, s)
	a.Wait()
	if destinationCalls.Load() != 1 || s.JobCounts()["succeeded"] != 1 {
		t.Fatalf("calls = %d, jobs = %#v", destinationCalls.Load(), s.JobCounts())
	}
}

func TestDuplicateWhilePendingDoesNotDuplicateIntent(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	a, s := testApp(t, Config{ForwardURL: destination.URL, AllowPrivateTargets: true, PollInterval: 5 * time.Millisecond})
	defer stopApp(t, a, s)
	send := func() int {
		r := httptest.NewRequest(http.MethodPost, "/inbox", strings.NewReader("same-body"))
		r.Header.Set("X-GitHub-Delivery", "same-delivery")
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if code := send(); code != http.StatusAccepted {
		t.Fatalf("first response = %d", code)
	}
	<-started
	if code := send(); code != http.StatusOK {
		t.Fatalf("duplicate response = %d", code)
	}
	close(release)
	a.Wait()
	if calls.Load() != 1 || s.JobCounts()["succeeded"] != 1 {
		t.Fatalf("calls = %d, jobs = %#v", calls.Load(), s.JobCounts())
	}
}

func TestSensitiveHeadersAreRemovedAcrossDataPaths(t *testing.T) {
	const (
		inboundSecret  = "inbound-canary-secret"
		orgSecret      = "organization-canary-secret"
		responseSecret = "response-canary-secret"
		outboundAuth   = "Bearer destination-only-credential"
	)
	forwarded := make(chan http.Header, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded <- r.Header.Clone()
		w.Header().Set("X-API-Key", responseSecret)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	var logs bytes.Buffer
	a, s := testApp(t, Config{
		ForwardURL:           destination.URL,
		ForwardAuthorization: outboundAuth,
		SensitiveHeaders:     []string{"X-Organization-Credential"},
		AllowPrivateTargets:  true,
		PollInterval:         5 * time.Millisecond,
		Logger:               slog.New(slog.NewTextHandler(&logs, nil)),
	})
	defer stopApp(t, a, s)
	r := httptest.NewRequest(http.MethodPost, "/inbox", strings.NewReader("safe body"))
	r.Header.Set("X-GitHub-Delivery", "delivery-1")
	r.Header.Set("Authorization", inboundSecret)
	r.Header.Set("X-API-Key", inboundSecret)
	r.Header.Set("X-Organization-Credential", orgSecret)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("capture response = %d", w.Code)
	}
	a.Wait()

	headers := <-forwarded
	if headers.Get("X-API-Key") != "" || headers.Get("X-Organization-Credential") != "" || headers.Get("Authorization") != outboundAuth {
		t.Fatalf("forwarded headers = %#v", headers)
	}
	items, _ := s.ListSummaries("", 0, 10)
	request, attempts, ok := s.Get(items[0].ID)
	if !ok || len(attempts) != 1 {
		t.Fatalf("stored request = %v, attempts = %#v", ok, attempts)
	}
	storedJSON, _ := json.Marshal(map[string]any{"request": request, "attempts": attempts})
	if bytes.Contains(storedJSON, []byte(inboundSecret)) || bytes.Contains(storedJSON, []byte(orgSecret)) || bytes.Contains(storedJSON, []byte(responseSecret)) || bytes.Contains(storedJSON, []byte(outboundAuth)) {
		t.Fatalf("stored data leaked a canary: %s", storedJSON)
	}
	for _, name := range []string{"Authorization", "X-API-Key", "X-Organization-Credential"} {
		if got := http.Header(request.Headers).Values(name); len(got) != 1 || got[0] != "[REDACTED]" {
			t.Fatalf("stored %s = %#v", name, got)
		}
	}
	if got := http.Header(attempts[0].ResponseHeaders).Values("X-API-Key"); len(got) != 1 || got[0] != "[REDACTED]" {
		t.Fatalf("stored response API key = %#v", got)
	}

	detail := httptest.NewRequest(http.MethodGet, "/api/requests/"+request.ID, nil)
	detail.Header.Set("Authorization", "Bearer operator")
	detailResponse := httptest.NewRecorder()
	a.Handler().ServeHTTP(detailResponse, detail)
	metrics := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	metrics.Header.Set("Authorization", "Bearer operator")
	metricsResponse := httptest.NewRecorder()
	a.Handler().ServeHTTP(metricsResponse, metrics)
	old, _, cancel, err := s.SubscribeFrom(0)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	eventsJSON, _ := json.Marshal(old)
	allOutput := append(append(append([]byte(nil), detailResponse.Body.Bytes()...), metricsResponse.Body.Bytes()...), eventsJSON...)
	allOutput = append(allOutput, logs.Bytes()...)
	for _, secret := range []string{inboundSecret, orgSecret, responseSecret, outboundAuth} {
		if bytes.Contains(allOutput, []byte(secret)) {
			t.Fatalf("output leaked %q", secret)
		}
		if _, total := s.ListSummaries(secret, 0, 10); total != 0 {
			t.Fatalf("search indexed secret %q", secret)
		}
	}
}

func TestRedactionPolicyIsCaseInsensitiveAndExtensible(t *testing.T) {
	policy := sensitiveHeaderPolicy([]string{"X-Organization-Key"})
	headers := http.Header{
		"x-api-key":          {"api-secret"},
		"X-AUTH-TOKEN":       {"token-secret"},
		"x-organization-key": {"org-secret"},
		"X-Safe":             {"safe"},
	}
	redacted := redactWithPolicy(headers, policy)
	for _, name := range []string{"x-api-key", "X-AUTH-TOKEN", "x-organization-key"} {
		if got := redacted[name]; len(got) != 1 || got[0] != "[REDACTED]" {
			t.Errorf("%s = %#v", name, got)
		}
	}
	if got := redacted["X-Safe"]; len(got) != 1 || got[0] != "safe" {
		t.Fatalf("safe header = %#v", got)
	}
}

func TestBodyLimitBoundary(t *testing.T) {
	a, s := testApp(t, Config{MaxBody: 4})
	defer stopApp(t, a, s)
	for body, want := range map[string]int{"1234": http.StatusAccepted, "12345": http.StatusRequestEntityTooLarge} {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/inbox", strings.NewReader(body)))
		if w.Code != want {
			t.Errorf("body %q response = %d, want %d", body, w.Code, want)
		}
	}
}
