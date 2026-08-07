package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/1337lean/relaybox/internal/store"
	webui "github.com/1337lean/relaybox/internal/web"
)

type Config struct {
	Store                             *store.Store
	Secret, ForwardURL, OperatorToken string
	ForwardAuthorization              string
	SensitiveHeaders                  []string
	MaxBody                           int64
	Attempts, Concurrency, QueueSize  int
	MaxInFlight                       int
	BaseBackoff, MaxBackoff           time.Duration
	LeaseDuration, PollInterval       time.Duration
	SearchTimeout                     time.Duration
	Client                            *http.Client
	Logger                            *slog.Logger
	IDSource                          func() (string, error)
	AllowPrivateTargets               bool
	SecureCookies                     bool
}

type App struct {
	c         Config
	mux       *http.ServeMux
	wake      chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	accepting atomic.Bool
	ingestSem chan struct{}
	sensitive map[string]struct{}
}

func New(c Config) *App {
	if c.MaxBody <= 0 {
		c.MaxBody = 1 << 20
	}
	if c.Attempts <= 0 {
		c.Attempts = 3
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.QueueSize <= 0 {
		c.QueueSize = c.Concurrency * 16
	}
	if c.MaxInFlight <= 0 {
		c.MaxInFlight = 64
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = 500 * time.Millisecond
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 30 * time.Second
	}
	if c.LeaseDuration <= 0 {
		c.LeaseDuration = 2 * time.Minute
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 250 * time.Millisecond
	}
	if c.SearchTimeout <= 0 {
		c.SearchTimeout = 2 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Client == nil {
		c.Client = secureClient(c.AllowPrivateTargets)
	} else if c.Client.CheckRedirect == nil {
		c.Client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	if c.IDSource == nil {
		c.IDSource = newID
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &App{
		c:         c,
		mux:       http.NewServeMux(),
		wake:      make(chan struct{}, max(1, c.QueueSize)),
		ctx:       ctx,
		cancel:    cancel,
		ingestSem: make(chan struct{}, c.MaxInFlight),
		sensitive: sensitiveHeaderPolicy(c.SensitiveHeaders),
	}
	a.accepting.Store(true)
	a.routes()
	if err := c.Store.RecoverLeases(time.Now().UTC()); err != nil {
		c.Logger.Error("recover forwarding leases", "error", err)
	}
	for i := 0; i < c.Concurrency; i++ {
		a.wg.Add(1)
		go a.worker(fmt.Sprintf("worker-%d-%p", i, a))
	}
	a.signalWork()
	return a
}

func secureClient(allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		// A proxy would resolve and connect to the destination itself, bypassing
		// the IP checks in DialContext. Forwarding therefore never inherits the
		// process-wide HTTP_PROXY/HTTPS_PROXY environment.
		Proxy:                  nil,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           32,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		DisableCompression:     true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if !allowPrivate && blockedIP(ip) {
				continue
			}
			return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		return nil, errors.New("target resolves only to blocked addresses")
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // shared address space, commonly used by overlay networks
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),  // documentation
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("64:ff9b::/96"), // IPv4/IPv6 translation can disguise a blocked IPv4 target
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"), // Teredo
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4
}

func blockedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *App) Handler() http.Handler { return security(a.mux) }

func (a *App) routes() {
	a.mux.HandleFunc("POST /inbox", a.ingest)
	a.mux.HandleFunc("POST /inbox/", a.ingest)
	a.mux.Handle("GET /api/requests", a.operator(http.HandlerFunc(a.list)))
	a.mux.Handle("GET /api/requests/{id}", a.operator(http.HandlerFunc(a.get)))
	a.mux.Handle("POST /api/requests/{id}/replay", a.operator(http.HandlerFunc(a.replay)))
	a.mux.Handle("GET /api/events", a.operator(http.HandlerFunc(a.events)))
	a.mux.Handle("GET /api/metrics", a.operator(http.HandlerFunc(a.metrics)))
	a.mux.Handle("POST /api/session", a.operator(http.HandlerFunc(a.session)))
	a.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if a.c.Store.Health() != nil {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	a.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !a.accepting.Load() || a.c.Store.Health() != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready\n"))
	})
	a.mux.Handle("GET /", http.FileServer(http.FS(webui.Files)))
}
func security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; script-src 'self'; style-src 'self'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) operator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		authorization := r.Header.Get("Authorization")
		got := strings.TrimPrefix(authorization, "Bearer ")
		expected := a.c.OperatorToken
		usedCookie := false
		if got == authorization {
			if c, e := r.Cookie("relaybox_operator"); e == nil {
				got = c.Value
				expected = sessionToken(a.c.OperatorToken)
				usedCookie = true
			} else {
				got = ""
			}
		}
		if a.c.OperatorToken == "" || len(got) != len(expected) || subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="relaybox"`)
			http.Error(w, "operator token required", http.StatusUnauthorized)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			origin := r.Header.Get("Origin")
			if usedCookie && origin == "" {
				http.Error(w, "origin required for cookie-authenticated request", http.StatusForbidden)
				return
			}
			if origin != "" && !a.sameOrigin(r, origin) {
				http.Error(w, "cross-origin request denied", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) sameOrigin(r *http.Request, rawOrigin string) bool {
	origin, err := url.Parse(rawOrigin)
	if err != nil || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	expectedScheme := "http"
	if r.TLS != nil || a.c.SecureCookies {
		expectedScheme = "https"
	}
	return strings.EqualFold(origin.Scheme, expectedScheme) && strings.EqualFold(origin.Host, r.Host)
}

func (a *App) session(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "relaybox_operator",
		Value:    sessionToken(a.c.OperatorToken),
		Path:     "/api/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil || a.c.SecureCookies,
		MaxAge:   8 * 60 * 60,
	})
	w.WriteHeader(204)
}

func sessionToken(operatorToken string) string {
	mac := hmac.New(sha256.New, []byte(operatorToken))
	mac.Write([]byte("relaybox/operator-session/v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *App) ingest(w http.ResponseWriter, r *http.Request) {
	if !a.accepting.Load() {
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	select {
	case a.ingestSem <- struct{}{}:
		defer func() { <-a.ingestSem }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many concurrent deliveries", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, a.c.MaxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "could not read request body", http.StatusBadRequest)
		}
		return
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	signatureVerified := a.c.Secret != "" && verify(a.c.Secret, r.Header.Get("X-Hub-Signature-256"), body)
	if a.c.Secret != "" && !signatureVerified {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	id, err := a.c.IDSource()
	if err != nil {
		http.Error(w, "entropy unavailable", 500)
		return
	}
	req := store.Request{ID: id, DeliveryID: r.Header.Get("X-GitHub-Delivery"), Method: r.Method, Path: r.URL.Path, RemoteAddr: r.RemoteAddr, BodySHA256: hash, ReceivedAt: time.Now().UTC(), Headers: a.redact(r.Header), Body: body, SignatureVerified: signatureVerified}
	var job *store.Job
	if a.c.ForwardURL != "" {
		if err := validateTarget(a.c.ForwardURL, a.c.AllowPrivateTargets); err != nil {
			http.Error(w, "invalid forwarding target", 500)
			return
		}
		jobID, idErr := a.c.IDSource()
		if idErr != nil {
			http.Error(w, "entropy unavailable", 500)
			return
		}
		job = &store.Job{ID: jobID, RequestID: req.ID, URL: a.c.ForwardURL, State: "pending", CreatedAt: time.Now().UTC()}
	}
	id, result, persistedJob, err := a.c.Store.Accept(req, job)
	if err != nil {
		if errors.Is(err, store.ErrCapacity) {
			http.Error(w, "retention capacity reached", http.StatusInsufficientStorage)
			return
		}
		http.Error(w, "storage failure", 500)
		return
	}
	if result == store.Conflict {
		jsonOut(w, 409, map[string]any{"id": id, "error": "delivery ID reused with different body"})
		return
	}
	if result == store.Duplicate {
		if persistedJob != nil && !terminalJobState(persistedJob.State) {
			a.signalWork()
		}
		jsonOut(w, 200, map[string]any{"id": id, "duplicate": true})
		return
	}
	if persistedJob != nil {
		a.signalWork()
	}
	jsonOut(w, 202, map[string]any{"id": id, "duplicate": false})
}
func verify(secret, sig string, body []byte) bool {
	if !strings.HasPrefix(sig, "sha256=") {
		return false
	}
	got, e := hex.DecodeString(strings.TrimPrefix(sig, "sha256="))
	if e != nil {
		return false
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hmac.Equal(got, m.Sum(nil))
}
func sensitiveHeaderPolicy(extra []string) map[string]struct{} {
	policy := map[string]struct{}{}
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie",
		"API-Key", "X-API-Key", "API-Token", "X-API-Token", "X-Auth-Token",
		"X-Access-Token", "X-Client-Token", "X-Token", "Secret-Key", "X-Secret-Key",
		"X-Secret", "X-Client-Secret", "X-Amz-Security-Token",
		"X-Hub-Signature", "X-Hub-Signature-256",
	} {
		policy[strings.ToLower(name)] = struct{}{}
	}
	for _, name := range extra {
		if name = strings.TrimSpace(name); name != "" {
			policy[strings.ToLower(name)] = struct{}{}
		}
	}
	return policy
}

func redactWithPolicy(h http.Header, policy map[string]struct{}) store.Header {
	out := store.Header{}
	for k, v := range h {
		if _, sensitive := policy[strings.ToLower(k)]; sensitive {
			out[k] = []string{"[REDACTED]"}
		} else {
			out[k] = append([]string(nil), v...)
		}
	}
	return out
}

func (a *App) redact(h http.Header) store.Header {
	return redactWithPolicy(h, a.sensitive)
}
func newID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func (a *App) list(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query().Get("q")) > 256 {
		http.Error(w, "search query too long", http.StatusBadRequest)
		return
	}
	limit := parseBounded(r.URL.Query().Get("limit"), 50, 1, 200)
	offset := parseBounded(r.URL.Query().Get("offset"), 0, 0, 1_000_000)
	ctx, cancel := context.WithTimeout(r.Context(), a.c.SearchTimeout)
	defer cancel()
	items, total, truncated, err := a.c.Store.ListSummariesContext(ctx, r.URL.Query().Get("q"), offset, limit)
	if err != nil {
		http.Error(w, "search budget exceeded", http.StatusServiceUnavailable)
		return
	}
	jsonOut(w, 200, map[string]any{"items": items, "total": total, "offset": offset, "limit": limit, "truncated": truncated})
}
func parseBounded(s string, def, min, max int) int {
	n, e := strconv.Atoi(s)
	if e != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}
func (a *App) get(w http.ResponseWriter, r *http.Request) {
	req, at, ok := a.c.Store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	jsonOut(w, 200, map[string]any{"request": req, "attempts": at})
}
func (a *App) replay(w http.ResponseWriter, r *http.Request) {
	req, _, ok := a.c.Store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if a.c.ForwardURL == "" {
		http.Error(w, "configured forward URL required", 400)
		return
	}
	if err := a.schedule(req, a.c.ForwardURL); err != nil {
		if errors.Is(err, store.ErrCapacity) {
			http.Error(w, "replay retention capacity reached", http.StatusInsufficientStorage)
			return
		}
		http.Error(w, "scheduling failed", 500)
		return
	}
	jsonOut(w, 202, map[string]string{"status": "scheduled"})
}
func ValidateForwardTarget(raw string, allowPrivate bool) error {
	return validateTarget(raw, allowPrivate)
}
func validateTarget(raw string, allowPrivate bool) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "http" && u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("invalid forwarding URL")
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !allowPrivate && blockedIP(ip) {
		return errors.New("blocked forwarding destination")
	}
	return nil
}
func (a *App) schedule(req store.Request, target string) error {
	if err := validateTarget(target, a.c.AllowPrivateTargets); err != nil {
		return err
	}
	id, e := a.c.IDSource()
	if e != nil {
		return e
	}
	j := store.Job{ID: id, RequestID: req.ID, URL: target, State: "pending", CreatedAt: time.Now().UTC()}
	if e = a.c.Store.Enqueue(j); e != nil {
		return e
	}
	a.signalWork()
	return nil
}

func (a *App) signalWork() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func terminalJobState(state string) bool {
	switch state {
	case "succeeded", "failed", "fatal", "dead-letter", "poison":
		return true
	default:
		return false
	}
}

func (a *App) worker(owner string) {
	defer a.wg.Done()
	ticker := time.NewTicker(a.c.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.wake:
		case <-ticker.C:
		case <-a.ctx.Done():
			return
		}
		for {
			j, ok, err := a.c.Store.ClaimNextJob(owner, time.Now().UTC(), a.c.LeaseDuration)
			if err != nil {
				a.c.Logger.Error("claim forwarding job", "error", err)
				break
			}
			if !ok {
				break
			}
			a.signalWork()
			a.forward(owner, j)
			if a.ctx.Err() != nil {
				return
			}
		}
	}
}
func (a *App) forward(owner string, j store.Job) {
	req, _, ok := a.c.Store.Get(j.RequestID)
	if !ok {
		if err := a.c.Store.FinishWithoutAttempt(j.ID, owner, "poison", "request missing"); err != nil {
			a.c.Logger.Error("persist poison job", "error", err, "job", j.ID)
		}
		return
	}
	n := a.c.Store.AttemptsForJob(j.ID) + 1
	attID, idErr := a.c.IDSource()
	if idErr != nil {
		if err := a.c.Store.FinishWithoutAttempt(j.ID, owner, "poison", "attempt ID unavailable"); err != nil {
			a.c.Logger.Error("persist poison job", "error", err, "job", j.ID)
		}
		return
	}
	started := time.Now().UTC()
	hr, requestErr := http.NewRequestWithContext(a.ctx, http.MethodPost, j.URL, bytes.NewReader(req.Body))
	if requestErr == nil {
		hr.Header = forwardHeaders(req.Headers)
		if a.c.ForwardAuthorization != "" {
			hr.Header.Set("Authorization", a.c.ForwardAuthorization)
		}
		hr.Header.Set("X-Relaybox-Request-ID", req.ID)
		hr.Header.Set("X-Relaybox-Job-ID", j.ID)
	}
	var status int
	var responseHeaders store.Header
	var responseBody []byte
	var retry time.Duration
	var retryValid bool
	if requestErr == nil {
		resp, doErr := a.c.Client.Do(hr)
		requestErr = doErr
		if resp != nil {
			status = resp.StatusCode
			responseHeaders = a.redact(resp.Header)
			responseBody, _ = io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			retry, retryValid = parseRetry(resp.Header.Get("Retry-After"), time.Now())
		}
	}
	finished := time.Now().UTC()
	att := store.Attempt{ID: attID, JobID: j.ID, RequestID: req.ID, URL: j.URL, Number: n, Status: status, StartedAt: started, FinishedAt: finished, ResponseHeaders: responseHeaders, ResponseBody: responseBody}
	if requestErr != nil {
		att.Error = requestErr.Error()
	}
	state := "succeeded"
	message := ""
	availableAt := time.Time{}
	switch {
	case requestErr == nil && status >= 200 && status < 300:
	case requestErr == nil && !retryStatus(status):
		state = "fatal"
		message = fmt.Sprintf("non-retryable status %d", status)
	case n >= a.c.Attempts:
		state = "dead-letter"
		message = "attempts exhausted"
	default:
		state = "retrying"
		if !retryValid {
			retry = a.backoff(j.ID, n)
		}
		if retry > a.c.MaxBackoff {
			retry = a.c.MaxBackoff
		}
		availableAt = finished.Add(retry)
	}
	if err := a.c.Store.RecordAttempt(j.ID, owner, att, state, message, availableAt); err != nil {
		a.c.Logger.Error("persist forwarding attempt", "error", err, "job", j.ID)
		return
	}
	if state == "retrying" {
		a.signalWork()
	}
}

func forwardHeaders(src store.Header) http.Header {
	drop := map[string]struct{}{
		"Connection":            {},
		"Keep-Alive":            {},
		"Proxy-Authenticate":    {},
		"Proxy-Authorization":   {},
		"Proxy-Connection":      {},
		"Te":                    {},
		"Trailer":               {},
		"Transfer-Encoding":     {},
		"Upgrade":               {},
		"Forwarded":             {},
		"X-Forwarded-For":       {},
		"X-Forwarded-Host":      {},
		"X-Forwarded-Proto":     {},
		"X-Real-Ip":             {},
		"X-Relaybox-Job-Id":     {},
		"X-Relaybox-Request-Id": {},
	}
	for _, value := range http.Header(src).Values("Connection") {
		for token := range strings.SplitSeq(value, ",") {
			if name := http.CanonicalHeaderKey(strings.TrimSpace(token)); name != "" {
				drop[name] = struct{}{}
			}
		}
	}

	dst := make(http.Header)
	for name, values := range src {
		name = http.CanonicalHeaderKey(name)
		if _, blocked := drop[name]; blocked || name == "" {
			continue
		}
		for _, value := range values {
			if value != "[REDACTED]" {
				dst.Add(name, value)
			}
		}
	}
	return dst
}
func retryStatus(s int) bool {
	return s == 0 || s == 408 || s == 425 || s == 429 || s >= 500 && s <= 599
}
func (a *App) backoff(job string, n int) time.Duration {
	base := float64(a.c.BaseBackoff) * math.Pow(2, float64(n-1))
	sum := sha256.Sum256([]byte(job + strconv.Itoa(n)))
	fraction := float64(uint16(sum[0])<<8|uint16(sum[1])) / 65535
	return time.Duration(base * (0.75 + 0.5*fraction))
}
func parseRetry(v string, now time.Time) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && seconds >= 0 {
		const maxRetrySeconds = int64((1<<63 - 1) / time.Second)
		if seconds > maxRetrySeconds {
			seconds = maxRetrySeconds
		}
		return time.Duration(seconds) * time.Second, true
	}
	if t, e := http.ParseTime(v); e == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

func (a *App) metrics(w http.ResponseWriter, _ *http.Request) {
	jsonOut(w, http.StatusOK, map[string]any{"forward_jobs": a.c.Store.JobCounts()})
}

func (a *App) events(w http.ResponseWriter, r *http.Request) {
	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "stream unsupported", 500)
		return
	}
	raw := r.Header.Get("Last-Event-ID")
	if raw == "" {
		raw = r.URL.Query().Get("cursor")
	}
	var seq uint64
	if raw == "" {
		seq = a.c.Store.Sequence()
	} else {
		var err error
		seq, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			http.Error(w, "invalid event cursor", http.StatusBadRequest)
			return
		}
	}
	old, ch, cancel, e := a.c.Store.SubscribeFrom(seq)
	if e != nil {
		if errors.Is(e, store.ErrEventBacklog) {
			http.Error(w, "event cursor is too old", http.StatusConflict)
		} else {
			http.Error(w, "event storage failure", 500)
		}
		return
	}
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	write := func(render func() error) bool {
		controller := http.NewResponseController(w)
		deadlineSet := controller.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if deadlineSet != nil && !errors.Is(deadlineSet, http.ErrNotSupported) {
			return false
		}
		if deadlineSet == nil {
			defer controller.SetWriteDeadline(time.Time{})
		}
		if err := render(); err != nil {
			return false
		}
		return controller.Flush() == nil
	}
	send := func(e store.Event) bool {
		b, err := json.Marshal(e)
		if err != nil {
			return false
		}
		return write(func() error {
			_, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.Seq, e.Kind, b)
			return err
		})
	}
	for _, e := range old {
		if !send(e) {
			return
		}
		seq = e.Seq
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return
			}
			if e.Seq <= seq {
				continue
			}
			if !send(e) {
				return
			}
			seq = e.Seq
		case <-tick.C:
			if !write(func() error {
				_, err := fmt.Fprint(w, ": heartbeat\n\n")
				return err
			}) {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}
func (a *App) Wait() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if len(a.c.Store.UnfinishedJobs()) == 0 {
			return
		}
		select {
		case <-ticker.C:
		case <-a.ctx.Done():
			return
		}
	}
}
func (a *App) Shutdown(ctx context.Context) error {
	a.accepting.Store(false)
	done := make(chan struct{})
	go func() { a.Wait(); close(done) }()
	select {
	case <-done:
		a.cancel()
		a.wg.Wait()
		return nil
	case <-ctx.Done():
		a.cancel()
		a.wg.Wait()
		return ctx.Err()
	}
}
func ShutdownServer(ctx context.Context, s *http.Server, a *App) error {
	a.accepting.Store(false)
	serverErr := s.Shutdown(ctx)
	appErr := a.Shutdown(ctx)
	return errors.Join(serverErr, appErr)
}

func EncodeBodyForCurl(body []byte) string { return base64.StdEncoding.EncodeToString(body) }
