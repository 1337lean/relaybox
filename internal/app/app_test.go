package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
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
