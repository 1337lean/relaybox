package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/1337lean/relaybox/internal/app"
	"github.com/1337lean/relaybox/internal/store"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "demo":
		demo(os.Args[2:])
	case "healthcheck":
		healthcheck(os.Args[2:])
	case "version":
		fmt.Println("relaybox", resolvedVersion())
	default:
		usage()
		os.Exit(2)
	}
}

func resolvedVersion() string {
	info, ok := debug.ReadBuildInfo()
	return resolveVersion(version, info, ok)
}

func resolveVersion(injected string, info *debug.BuildInfo, ok bool) string {
	if injected = strings.TrimPrefix(strings.TrimSpace(injected), "v"); injected != "" && injected != "dev" {
		return injected
	}
	if !ok || info == nil {
		return "dev"
	}
	built := strings.TrimPrefix(strings.TrimSpace(info.Main.Version), "v")
	if built == "" || built == "(devel)" {
		return "dev"
	}
	return built
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: relaybox <serve|demo|healthcheck|version>")
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	data := fs.String("data", filepath.Join("data", "relaybox.ndjson"), "store path")
	secret := fs.String("secret", os.Getenv("RELAYBOX_SECRET"), "GitHub HMAC secret (or RELAYBOX_SECRET)")
	forward := fs.String("forward", "", "fixed forward URL")
	token := fs.String("operator-token", os.Getenv("RELAYBOX_OPERATOR_TOKEN"), "operator bearer token (or RELAYBOX_OPERATOR_TOKEN; generated if empty)")
	max := fs.Int64("max-body", 1<<20, "maximum request body bytes")
	attempts := fs.Int("attempts", 3, "forward attempts")
	conc := fs.Int("concurrency", 4, "forward worker count")
	queue := fs.Int("queue-size", 64, "bounded forwarding wake-up hint buffer size")
	maxInFlight := fs.Int("max-inflight", 64, "maximum concurrent inbox body reads")
	retentionCaptures := fs.Int("retention-captures", 1000, "maximum retained captures")
	retentionEvents := fs.Int("retention-events", 100000, "event count that triggers log compaction")
	jobsPerRequest := fs.Int("jobs-per-request", 8, "maximum retained forwarding jobs per capture")
	searchBytes := fs.Int("search-bytes", 64<<10, "maximum indexed body bytes per capture")
	allowPrivate := fs.Bool("allow-private-targets", false, "allow private/link-local/loopback forwarding (development only)")
	secureCookies := fs.Bool("secure-cookie", false, "always mark the operator cookie Secure (use behind TLS termination)")
	fs.Parse(args)
	if *max < 1 || *max > 64<<20 {
		log.Fatal("-max-body must be between 1 byte and 64 MiB")
	}
	if *attempts < 1 || *attempts > 10 {
		log.Fatal("-attempts must be between 1 and 10")
	}
	if *conc < 1 || *conc > 128 {
		log.Fatal("-concurrency must be between 1 and 128")
	}
	if *queue < 1 || *queue > 100_000 {
		log.Fatal("-queue-size must be between 1 and 100000")
	}
	if *maxInFlight < 1 || *maxInFlight > 10_000 {
		log.Fatal("-max-inflight must be between 1 and 10000")
	}
	if *retentionCaptures < 1 || *retentionCaptures > 1_000_000 {
		log.Fatal("-retention-captures must be between 1 and 1000000")
	}
	if *retentionEvents < 100 || *retentionEvents > 10_000_000 {
		log.Fatal("-retention-events must be between 100 and 10000000")
	}
	if *jobsPerRequest < 1 || *jobsPerRequest > 1000 {
		log.Fatal("-jobs-per-request must be between 1 and 1000")
	}
	if *searchBytes < 1 || *searchBytes > 1<<20 {
		log.Fatal("-search-bytes must be between 1 byte and 1 MiB")
	}
	if *forward != "" {
		if err := app.ValidateForwardTarget(*forward, *allowPrivate); err != nil {
			log.Fatalf("invalid -forward: %v", err)
		}
	}
	if *token == "" {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		*token = hex.EncodeToString(b)
		log.Printf("generated operator token: %s", *token)
	}
	if len(*token) < 24 {
		log.Print("warning: operator token is short; use at least 24 random characters outside development")
	}
	if *secret == "" {
		log.Print("warning: inbox signature verification is disabled; set RELAYBOX_SECRET for untrusted networks")
	}
	st, err := store.OpenWithOptions(*data, store.Options{
		MaxCaptures:       *retentionCaptures,
		MaxEvents:         *retentionEvents,
		MaxJobsPerRequest: *jobsPerRequest,
		MaxAttemptsPerJob: *attempts,
		MaxSearchBytes:    *searchBytes,
		MaxSearchScan:     *retentionCaptures,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	a := app.New(app.Config{
		Store:                st,
		Secret:               *secret,
		ForwardURL:           *forward,
		OperatorToken:        *token,
		ForwardAuthorization: os.Getenv("RELAYBOX_FORWARD_AUTHORIZATION"),
		SensitiveHeaders:     splitCommaList(os.Getenv("RELAYBOX_SENSITIVE_HEADERS")),
		MaxBody:              *max,
		Attempts:             *attempts,
		Concurrency:          *conc,
		QueueSize:            *queue,
		MaxInFlight:          *maxInFlight,
		AllowPrivateTargets:  *allowPrivate,
		SecureCookies:        *secureCookies,
	})
	srv := &http.Server{
		Addr:              *addr,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		// SSE responses use per-write deadlines in the handler.
		WriteTimeout:   0,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("Relaybox listening on http://%s", *addr)
		errCh <- srv.ListenAndServe()
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := app.ShutdownServer(shutdown, srv, a); err != nil {
		log.Print(err)
	}
}

func splitCommaList(value string) []string {
	var out []string
	for name := range strings.SplitSeq(value, ",") {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func healthcheck(args []string) {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	base := fs.String("url", "http://127.0.0.1:8080/readyz", "readiness URL")
	fs.Parse(args)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(*base)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("healthcheck returned %s", resp.Status)
	}
}

func demo(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	base := fs.String("url", "http://127.0.0.1:8080/inbox", "inbox URL")
	fs.Parse(args)
	payload := []byte(`{"event":"relaybox.demo","message":"Hello from Relaybox"}`)
	request, err := http.NewRequest(http.MethodPost, *base, bytes.NewReader(payload))
	if err != nil {
		log.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println("demo delivery:", resp.Status)
}
