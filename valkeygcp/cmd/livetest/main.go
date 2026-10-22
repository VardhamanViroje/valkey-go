// Command livetest exercises valkeygcp against a real Memorystore for Valkey instance and
// logs evidence for each feature: every AUTH (first dial and proactive refresh) with a token
// fingerprint, from valkeygcp's OnAuth events, credential errors absorbed by the
// last-known-good logic, per-node PINGs and a final machine-readable RESULT line.
//
// Run it on a VM in the instance's VPC network. Tokens are never printed, only 12 hex digits
// of a fingerprint, so a rotation shows up as a new value: AUTH lines carry valkeygcp's
// (hmac:, keyed per process), -mode=token the token's SHA-256 (sha256:).
//
//	livetest -mode=resolve -instance=projects/P/locations/R/instances/I
//	livetest -mode=token   -impersonate-sa=sa@proj.iam.gserviceaccount.com
//	livetest -mode=once    -instance=projects/P/locations/R/instances/I
//	livetest -mode=soak    -instance=projects/P/locations/R/instances/I -duration=70m
//	livetest -mode=storm   -discovery=10.0.0.15:6379 -auth=iam -clients=50
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
	"github.com/valkey-io/valkey-go/valkeygcp/cas"
)

var (
	mode = flag.String("mode", "once", "resolve | token | once | soak | storm")

	// Instance and endpoints (valkeygcp.Config).
	instance  = flag.String("instance", "", "projects/P/locations/R/instances/I: auto-discovery path")
	network   = flag.String("network", "", "VPC network of the PSC endpoint group (optional)")
	discovery = flag.String("discovery", "", "discovery endpoint IP:port (cluster mode, explicit path)")
	primary   = flag.String("primary", "", "primary endpoint IP:port (cluster mode disabled, explicit path)")
	reader    = flag.String("reader", "", "reader endpoint IP:port (cluster mode disabled, optional)")
	authMode  = flag.String("auth", "auto", "auto | disabled | iam | token")
	tlsMode   = flag.String("tls", "auto", "auto | disabled | per-instance | shared | custom")
	caFile    = flag.String("ca-file", "", "server CA PEM bundle (explicit path or customer-managed CA)")
	casFetch  = flag.Bool("cas-fetch", false, "read a customer-managed CA from the instance's CA Service pool (TLS.FetchCustomCA)")

	// IAM (valkeygcp.IAMAuthOptions).
	iamUser       = flag.String("iam-username", "", "explicit IAM AUTH username (wins over -username-strategy)")
	userStrategy  = flag.String("username-strategy", "default", "default | principal-email")
	impersonateSA = flag.String("impersonate-sa", "", "service account to impersonate")
	impLifetime   = flag.Duration("impersonate-lifetime", 0, "impersonated token lifetime (0 = 1h; above 1h needs the org policy)")
	credsFile     = flag.String("credentials-json", "", "path to a service account key or WIF credential config")
	refreshBuffer = flag.Duration("refresh-buffer", 0, "IAM refresh buffer (0 = 5m)")
	fetchTimeout  = flag.Duration("fetch-timeout", 0, "cap on one IAM token fetch (0 = 10s, negative = no cap)")
	maxAuthPerSec = flag.Float64("max-auth-per-second", 0, "pace token-backed AUTHs per client (0 = off)")
	disableReauth = flag.Bool("disable-reauth", false, "turn off proactive re-AUTH on live connections")

	// Token Auth (valkeygcp.TokenAuthOptions).
	tokenSecret = flag.String("token-secret", "", "Secret Manager version holding the TOKEN_AUTH token")
	tokenStatic = flag.String("token", "", "static TOKEN_AUTH token (development only; prefer -token-secret)")
	tokenUser   = flag.String("token-user", "", "token-auth username (empty = default user)")
	tokenReload = flag.Duration("token-reload", 0, "token re-read interval (0 = 5m, negative = never)")

	// valkey-go option passed through valkeygcp.Config.ClientOption.
	disableCache = flag.Bool("disable-cache", false, "set ClientOption.DisableCache: no CLIENT TRACKING in the handshake (ACL workaround)")

	// Run control.
	setupTimeout = flag.Duration("setup-timeout", 2*time.Minute, "deadline for discovery, credential setup and connecting")
	duration     = flag.Duration("duration", 70*time.Minute, "soak: how long to run")
	interval     = flag.Duration("interval", 200*time.Millisecond, "soak: pause between SET/GET pairs")
	reportEvery  = flag.Duration("report-every", time.Minute, "soak: how often to log STATS")
	clients      = flag.Int("clients", 50, "storm: number of clients created at the same moment")
)

// Counters shared by the AUTH wrapper, the credential-error callback and the traffic loop.
var (
	authOK, authErr, credErr, opsOK, opsFail atomic.Int64
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	logStart()

	cfg, err := buildConfig()
	if err != nil {
		log.Printf("CONFIG_ERROR %v", err)
		os.Exit(2)
	}
	var ok bool
	switch *mode {
	case "resolve":
		ok = runResolve(cfg)
	case "token":
		ok = runToken(cfg)
	case "once":
		ok = runOnce(cfg)
	case "soak":
		ok = runSoak(cfg)
	case "storm":
		ok = runStorm(cfg)
	default:
		log.Printf("CONFIG_ERROR unknown -mode %q", *mode)
		os.Exit(2)
	}
	if !ok {
		os.Exit(1)
	}
}

// logStart records the flags that were set, without secret values.
func logStart() {
	var set []string
	flag.Visit(func(f *flag.Flag) {
		v := f.Value.String()
		if f.Name == "token" {
			v = "<redacted>"
		}
		set = append(set, "-"+f.Name+"="+v)
	})
	host, _ := os.Hostname()
	log.Printf("START host=%s flags=%s", host, strings.Join(set, " "))
}

func buildConfig() (valkeygcp.Config, error) {
	cfg := valkeygcp.Config{
		Instance:          *instance,
		Network:           *network,
		DiscoveryEndpoint: *discovery,
		PrimaryEndpoint:   *primary,
		ReaderEndpoint:    *reader,
		TLS:               valkeygcp.TLSOptions{CAFile: *caFile},
		Auth: valkeygcp.AuthOptions{
			OnCredentialError: func(err error) {
				credErr.Add(1)
				log.Printf("CREDENTIAL_ERROR absorbed (last-known-good token kept): %v", err)
			},
		},
		// The name shows up in CLIENT LIST (name=valkeygcp-livetest) on every node.
		ClientOption: valkey.ClientOption{ClientName: "valkeygcp-livetest", DisableCache: *disableCache},
	}

	switch *authMode {
	case "auto":
	case "disabled":
		cfg.Auth.Mode = valkeygcp.AuthDisabled
	case "iam":
		cfg.Auth.Mode = valkeygcp.AuthIAM
	case "token":
		cfg.Auth.Mode = valkeygcp.AuthToken
	default:
		return cfg, fmt.Errorf("-auth=%q: want auto, disabled, iam or token", *authMode)
	}

	if *casFetch {
		cfg.TLS.FetchCustomCA = cas.FetchPoolCAs
	}
	switch *tlsMode {
	case "auto":
	case "disabled":
		cfg.TLS.Mode = valkeygcp.TLSDisabled
	case "per-instance":
		cfg.TLS.Mode = valkeygcp.TLSPerInstanceCA
	case "shared":
		cfg.TLS.Mode = valkeygcp.TLSSharedCA
	case "custom":
		cfg.TLS.Mode = valkeygcp.TLSCustomCA
	default:
		return cfg, fmt.Errorf("-tls=%q: want auto, disabled, per-instance, shared or custom", *tlsMode)
	}

	iam := valkeygcp.IAMAuthOptions{
		Username:               *iamUser,
		ImpersonateSA:          *impersonateSA,
		ImpersonateLifetime:    *impLifetime,
		RefreshBuffer:          *refreshBuffer,
		FetchTimeout:           *fetchTimeout,
		MaxAuthPerSecond:       *maxAuthPerSec,
		DisableProactiveReauth: *disableReauth,
	}
	switch *userStrategy {
	case "default":
	case "principal-email":
		iam.UsernameStrategy = valkeygcp.UsernamePrincipalEmail
	default:
		return cfg, fmt.Errorf("-username-strategy=%q: want default or principal-email", *userStrategy)
	}
	if *credsFile != "" {
		b, err := os.ReadFile(*credsFile)
		if err != nil {
			return cfg, fmt.Errorf("-credentials-json: %w", err)
		}
		iam.CredentialsJSON = b
	}
	cfg.Auth.IAM = iam

	if *tokenSecret != "" || *tokenStatic != "" {
		cfg.Auth.Token = valkeygcp.TokenAuthOptions{
			SecretVersion:  *tokenSecret,
			Token:          *tokenStatic,
			Username:       *tokenUser,
			ReloadInterval: *tokenReload,
		}
	}
	return cfg, nil
}

// connect builds the client with valkeygcp.NewClient and logs every credential hand-out
// through Auth.OnAuth: valkey-go asks for credentials on every new connection and again at
// RefreshAfter for the proactive re-AUTH. tag prefixes the log lines in storm mode.
func connect(ctx context.Context, cfg valkeygcp.Config, tag string) (valkey.Client, error) {
	cfg.Auth.OnAuth = logAuth(tag)
	client, err := valkeygcp.NewClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	log.Printf("%sCONNECTED mode=%s nodes=%d", tag, client.Mode(), len(client.Nodes()))
	return client, nil
}

// logAuth logs one AuthEvent per credential hand-out.
func logAuth(tag string) func(valkeygcp.AuthEvent) {
	return func(ev valkeygcp.AuthEvent) {
		if ev.Err != nil {
			authErr.Add(1)
			log.Printf("%sAUTH_ERROR addr=%s user=%s err=%v", tag, ev.Address, ev.Username, ev.Err)
			return
		}
		authOK.Add(1)
		token := "none(AUTH-skipped)" // empty credentials: valkey-go skips AUTH
		if ev.Fingerprint != "" {
			token = "hmac:" + ev.Fingerprint // valkeygcp's per-process keyed fingerprint
		}
		next := "none"
		if !ev.RefreshAfter.IsZero() {
			next = fmt.Sprintf("%s(in %s)", ev.RefreshAfter.UTC().Format(time.RFC3339),
				time.Until(ev.RefreshAfter).Round(time.Second))
		}
		var extra string
		if ev.Fallback {
			extra += " fallback=true" // a fetch failed; the last-known-good token was served
		}
		if ev.Plaintext {
			extra += " plaintext=true" // no TLS on this connection
		}
		log.Printf("%sAUTH addr=%s user=%s token=%s refreshAfter=%s%s", tag, ev.Address, ev.Username, token, next, extra)
	}
}

// fingerprint identifies a secret without revealing it. Empty credentials mean valkey-go
// skips AUTH (valkeygcp returns them when the last token expired during an outage).
func fingerprint(secret string) string {
	if secret == "" {
		return "none(AUTH-skipped)"
	}
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:6])
}

func result(fields map[string]any) {
	fields["mode"] = *mode
	fields["auths"] = authOK.Load()
	fields["authErrors"] = authErr.Load()
	fields["credentialErrors"] = credErr.Load()
	b, err := json.Marshal(fields)
	if err != nil {
		log.Printf("RESULT {\"marshalError\":%q}", err.Error())
		return
	}
	log.Printf("RESULT %s", b)
}

func fail(stage string, err error, start time.Time) bool {
	log.Printf("%s %v", stage, err)
	result(map[string]any{"ok": false, "stage": stage, "error": err.Error(),
		"elapsed": time.Since(start).Round(time.Millisecond).String()})
	return false
}

// runResolve settles the configuration without dialing. With IAM it also runs credential
// setup; with Token Auth it reads the token once, as valkeygcp.NewClient would.
func runResolve(cfg valkeygcp.Config) bool {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), *setupTimeout)
	defer cancel()
	opt, err := valkeygcp.ResolveClientOption(ctx, cfg)
	if err != nil {
		return fail("SETUP_ERROR", err, start)
	}
	log.Printf("RESOLVED init=%v replicas=%v sendToReplicas=%t tls=%t auth=%t dialTimeout=%s",
		opt.InitAddress, opt.Standalone.ReplicaAddress, opt.SendToReplicas != nil,
		opt.TLSConfig != nil, opt.AuthCredentialsFn != nil, opt.Dialer.Timeout)
	result(map[string]any{"ok": true, "init": opt.InitAddress, "replicas": opt.Standalone.ReplicaAddress,
		"tls": opt.TLSConfig != nil, "auth": opt.AuthCredentialsFn != nil,
		"elapsed": time.Since(start).Round(time.Millisecond).String()})
	return true
}

// runToken builds only the IAM token provider and fetches one token: ADC, a credentials
// file, or impersonation, plus the resolved AUTH username.
func runToken(cfg valkeygcp.Config) bool {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), *setupTimeout)
	defer cancel()
	p, err := valkeygcp.NewGCPTokenProvider(ctx, cfg.Auth.IAM)
	if err != nil {
		return fail("SETUP_ERROR", err, start)
	}
	tok, err := p.Token(ctx)
	if err != nil {
		return fail("TOKEN_ERROR", err, start)
	}
	creds, err := p.AuthCredentialsFn()(valkey.AuthCredentialsContext{})
	if err != nil {
		return fail("TOKEN_ERROR", err, start)
	}
	log.Printf("TOKEN type=%s expiry=%s(in %s) token=%s user=%s", tok.TokenType,
		tok.Expiry.UTC().Format(time.RFC3339), time.Until(tok.Expiry).Round(time.Second),
		fingerprint(tok.AccessToken), creds.Username)
	result(map[string]any{"ok": true, "user": creds.Username, "token": fingerprint(tok.AccessToken),
		"expiresIn": time.Until(tok.Expiry).Round(time.Second).String()})
	return true
}

// runOnce connects, PINGs every node (each node is a separate connection and AUTH, and with
// TLS a separate certificate check against that node's IP), then runs SET and GET.
func runOnce(cfg valkeygcp.Config) bool {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), *setupTimeout)
	defer cancel()
	client, err := connect(ctx, cfg, "")
	if err != nil {
		return fail("SETUP_ERROR", err, start)
	}
	defer client.Close()

	addrs, failedNodes := pingNodes(ctx, client)
	key := fmt.Sprintf("livetest:once:%d", time.Now().UnixNano())
	sgErr := setGet(ctx, client, key, "ok")
	sg := "ok"
	if sgErr != nil {
		sg = sgErr.Error()
		log.Printf("OP_FAIL %v", sgErr)
	} else {
		log.Printf("SET/GET %s ok", key)
	}
	ok := failedNodes == 0 && sgErr == nil
	result(map[string]any{"ok": ok, "clientMode": string(client.Mode()), "nodes": addrs,
		"failedNodes": failedNodes, "setGet": sg,
		"elapsed": time.Since(start).Round(time.Millisecond).String()})
	return ok
}

// runSoak keeps SET/GET traffic going for -duration (or until Ctrl+C) and logs STATS, so
// proactive re-AUTH, token rotation and forced reconnects can be watched in the log.
func runSoak(cfg valkeygcp.Config) bool {
	start := time.Now()
	setupCtx, cancelSetup := context.WithTimeout(context.Background(), *setupTimeout)
	client, err := connect(setupCtx, cfg, "")
	cancelSetup()
	if err != nil {
		return fail("SETUP_ERROR", err, start)
	}
	defer client.Close()

	sigCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	runCtx, cancelRun := context.WithTimeout(sigCtx, *duration)
	defer cancelRun()

	addrs, _ := pingNodes(runCtx, client)
	host, _ := os.Hostname()
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	report := time.NewTicker(*reportEvery)
	defer report.Stop()

	var n int64
	for {
		select {
		case <-runCtx.Done():
			logStats(start)
			ok := opsFail.Load() == 0 && opsOK.Load() > 0
			result(map[string]any{"ok": ok, "clientMode": string(client.Mode()), "nodes": addrs,
				"opsOK": opsOK.Load(), "opsFailed": opsFail.Load(),
				"elapsed": time.Since(start).Round(time.Second).String()})
			return ok
		case <-report.C:
			logStats(start)
		case <-tick.C:
			n++
			opCtx, cancelOp := context.WithTimeout(runCtx, 5*time.Second)
			err := setGet(opCtx, client, fmt.Sprintf("livetest:soak:%s:%d", host, n%100), strconv.FormatInt(n, 10))
			cancelOp()
			switch {
			case err == nil:
				opsOK.Add(1)
			case runCtx.Err() != nil:
				// Stopping: an operation cut short by the end of the run isn't a failure.
			default:
				opsFail.Add(1)
				log.Printf("OP_FAIL n=%d err=%v", n, err)
			}
		}
	}
}

func logStats(start time.Time) {
	log.Printf("STATS elapsed=%s opsOK=%d opsFailed=%d auths=%d authErrors=%d credentialErrors=%d",
		time.Since(start).Round(time.Second), opsOK.Load(), opsFail.Load(),
		authOK.Load(), authErr.Load(), credErr.Load())
}

// runStorm creates -clients clients at the same moment, each with its own token provider,
// like that many processes restarting at once, and summarises how they connected.
func runStorm(cfg valkeygcp.Config) bool {
	ctx, cancel := context.WithTimeout(context.Background(), *setupTimeout)
	defer cancel()

	type outcome struct {
		took time.Duration
		err  error
	}
	out := make([]outcome, *clients)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := range out {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-gate
			t0 := time.Now()
			c, err := connect(ctx, cfg, fmt.Sprintf("[c%03d] ", i))
			if err == nil {
				err = c.Do(ctx, c.B().Ping().Build()).Error()
				c.Close()
			}
			out[i] = outcome{took: time.Since(t0), err: err}
		}(i)
	}
	start := time.Now()
	close(gate)
	wg.Wait()

	errorsByKind := map[string]int{}
	var took []time.Duration
	for i, o := range out {
		if o.err != nil {
			errorsByKind[classify(o.err)]++
			log.Printf("[c%03d] CLIENT_FAIL took=%s err=%v", i, o.took.Round(time.Millisecond), o.err)
			continue
		}
		took = append(took, o.took)
	}
	sort.Slice(took, func(a, b int) bool { return took[a] < took[b] })
	ok := len(took) == *clients
	result(map[string]any{"ok": ok, "clients": *clients, "connected": len(took), "errors": errorsByKind,
		"p50": percentile(took, 50), "p95": percentile(took, 95), "max": percentile(took, 100),
		"wall": time.Since(start).Round(time.Millisecond).String()})
	return ok
}

func classify(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "ERR_IAM_EXHAUSTED"):
		return "ERR_IAM_EXHAUSTED"
	case strings.Contains(s, "ERR_IAM_OTHER"):
		return "ERR_IAM_OTHER"
	case strings.Contains(s, "WRONGPASS"):
		return "WRONGPASS"
	case strings.Contains(s, "NOAUTH"):
		return "NOAUTH"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	}
	return "other"
}

func percentile(sorted []time.Duration, p int) string {
	if len(sorted) == 0 {
		return "n/a"
	}
	return sorted[(len(sorted)-1)*p/100].Round(time.Millisecond).String()
}

func pingNodes(ctx context.Context, client valkey.Client) ([]string, int) {
	nodes := client.Nodes()
	addrs := make([]string, 0, len(nodes))
	for a := range nodes {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	failed := 0
	for _, a := range addrs {
		n := nodes[a]
		if err := n.Do(ctx, n.B().Ping().Build()).Error(); err != nil {
			failed++
			log.Printf("NODE_FAIL addr=%s err=%v", a, err)
			continue
		}
		log.Printf("NODE_OK addr=%s", a)
	}
	return addrs, failed
}

func setGet(ctx context.Context, c valkey.Client, key, val string) error {
	// SET of a fixed value is idempotent, so it is marked retryable: a connection killed in
	// the middle of a command (CLIENT KILL, failover) is retried like the read-only GET.
	if err := c.Do(ctx, c.B().Set().Key(key).Value(val).Ex(2*time.Minute).Build().ToRetryable()).Error(); err != nil {
		return fmt.Errorf("SET %s: %w", key, err)
	}
	// On a cluster-disabled instance with a reader endpoint the GET goes to a replica, and
	// "the replica can lag by a few seconds" (Memorystore instance and node specification).
	// So a nil or older value is read again for up to 2s, and a STALE_READ line records it;
	// errors are returned at once.
	start, retries := time.Now(), 0
	deadline := start.Add(2 * time.Second)
	for {
		got, err := c.Do(ctx, c.B().Get().Key(key).Build()).ToString()
		switch {
		case err == nil && got == val:
			if retries > 0 {
				log.Printf("STALE_READ key=%s retries=%d waited=%s", key, retries, time.Since(start).Round(time.Millisecond))
			}
			return nil
		case err != nil && !valkey.IsValkeyNil(err):
			return fmt.Errorf("GET %s: %w", key, err)
		case time.Now().After(deadline):
			if err != nil {
				return fmt.Errorf("GET %s: %w (still after 2s of retries)", key, err)
			}
			return fmt.Errorf("GET %s: got %q, want %q (still after 2s of retries)", key, got, val)
		}
		retries++
		select {
		case <-ctx.Done():
			return fmt.Errorf("GET %s: %w", key, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
