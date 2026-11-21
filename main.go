package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// version is set at release time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

const identityHeader = "X-Authenticated-Principal"
const requestHeader = "X-Token-Request"

type config struct {
	Issuer                string              `json:"issuer"`
	PrivateKeyFile        string              `json:"private_key_file"`
	PreviousPublicKeysDir string              `json:"previous_public_keys_dir"`
	TokenLifetimeSeconds  int                 `json:"token_lifetime_seconds"`
	Subjects              map[string][]string `json:"subjects"`
}

func (c config) validate() error {
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.HasSuffix(c.Issuer, "/") || strings.Contains(u.Path, "//") {
		return errors.New("issuer must be a canonical HTTPS URL without credentials, query, fragment, or trailing slash")
	}
	if c.PrivateKeyFile == "" || !filepath.IsAbs(c.PrivateKeyFile) {
		return errors.New("private_key_file must be an absolute path")
	}
	if c.TokenLifetimeSeconds < 30 || c.TokenLifetimeSeconds > 900 {
		return errors.New("token_lifetime_seconds must be between 30 and 900")
	}
	if len(c.Subjects) == 0 {
		return errors.New("at least one subject and audience is required")
	}
	for subject, audiences := range c.Subjects {
		if strings.TrimSpace(subject) != subject || subject == "" || len(audiences) == 0 {
			return errors.New("every subject must have at least one explicit audience")
		}
		for _, audience := range audiences {
			if audience == "" || audience == "*" || strings.TrimSpace(audience) != audience {
				return errors.New("audiences must be nonempty explicit values, not wildcards")
			}
		}
	}
	return nil
}

func readConfig(path string) (config, error) {
	var c config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65536))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("config must contain exactly one JSON object")
	}
	return c, c.validate()
}

type publicJWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func jwkFor(key *rsa.PublicKey) publicJWK {
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	// RFC 7638 RSA thumbprint: canonical JSON with e, kty, n in lexical order.
	thumbprint := sha256.Sum256([]byte(fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n)))
	return publicJWK{"RSA", "sig", "RS256", base64.RawURLEncoding.EncodeToString(thumbprint[:]), n, e}
}

// parseRSAKey accepts an unencrypted PKCS#8 or PKCS#1 PEM RSA private key.
func parseRSAKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("signing key is not PEM encoded")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		if key, ok = parsed.(*rsa.PrivateKey); !ok {
			return nil, errors.New("signing key must be RSA")
		}
	case "RSA PRIVATE KEY":
		var err error
		if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported signing key PEM type " + block.Type)
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("RSA signing key must be at least 2048 bits")
	}
	return key, key.Validate()
}

// loadKey reads an existing signing key and refuses anything but a regular
// file readable only by its owner. It never creates or modifies files.
func loadKey(path string) (*rsa.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("signing key must be a regular file readable only by its owner")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseRSAKey(data)
}

// createKey writes a new key atomically: the complete key is flushed to a
// private temporary file and then hard-linked into place, so a crash can never
// leave a truncated key at path, and an existing file is never replaced.
func createKey(path string) (*rsa.PrivateKey, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp) // stale leftover from an interrupted earlier start
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)
	err = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if err := os.Link(tmp, path); err != nil { // fails if path already exists
		return nil, err
	}
	if d, err := os.Open(dir); err == nil { // persist the directory entry
		_ = d.Sync()
		d.Close()
	}
	return key, nil
}

func loadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return createKey(path)
	}
	return loadKey(path)
}

// limiter is a per-subject token bucket. Keys are only subjects that already
// passed authorization, so the map is bounded by the configuration.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{rate: rate, burst: burst, buckets: map[string]*bucket{}}
}

// allow takes one token, or reports how long until one is available.
func (l *limiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// Mint rate limit: sustained 30 per minute per subject, bursts of 10. Applied
// after authentication, unlike an nginx limit_req which runs before it.
const (
	mintRatePerSecond = 0.5
	mintBurst         = 10
)

type issuer struct {
	config config
	key    *rsa.PrivateKey
	kid    string
	jwks   []publicJWK
	prefix string
	origin string
	now    func() time.Time
	limit  *limiter
	header string // precomputed base64url JWS header
	// Metadata documents are immutable after startup, so encode them once.
	discoveryJSON, jwksJSON []byte
}

func newIssuer(c config, key *rsa.PrivateKey) (*issuer, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	u, _ := url.Parse(c.Issuer)
	active := jwkFor(&key.PublicKey)
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": active.Kid, "typ": "JWT"})
	i := &issuer{config: c, key: key, kid: active.Kid, jwks: []publicJWK{active}, prefix: u.Path, origin: u.Scheme + "://" + u.Host,
		now: time.Now, limit: newLimiter(mintRatePerSecond, mintBurst), header: base64.RawURLEncoding.EncodeToString(header)}
	if c.PreviousPublicKeysDir != "" {
		files, err := filepath.Glob(filepath.Join(c.PreviousPublicKeysDir, "*.pem"))
		if err != nil {
			return nil, err
		}
		for _, path := range files {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			block, _ := pem.Decode(data)
			if block == nil || block.Type != "PUBLIC KEY" {
				return nil, fmt.Errorf("previous key %s must contain a public key only", path)
			}
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			public, ok := parsed.(*rsa.PublicKey)
			if !ok || public.N.BitLen() < 2048 {
				return nil, errors.New("previous keys must be RSA public keys of at least 2048 bits")
			}
			jwk := jwkFor(public)
			if !slices.ContainsFunc(i.jwks, func(k publicJWK) bool { return k.Kid == jwk.Kid }) {
				i.jwks = append(i.jwks, jwk)
			}
		}
	}
	// Federation discovery only. Do not advertise OAuth flows we don't implement.
	i.discoveryJSON, _ = json.Marshal(map[string]any{
		"issuer": c.Issuer, "jwks_uri": c.Issuer + "/jwks.json",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
	i.jwksJSON, _ = json.Marshal(map[string]any{"keys": i.jwks})
	return i, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func failure(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// publicJSON serves an immutable public document. Consumers poll these, so they
// may be cached briefly; key rotation keeps old keys published for far longer.
func publicJSON(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	}
}

func (i *issuer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET "+i.prefix+"/.well-known/openid-configuration", publicJSON(i.discoveryJSON))
	mux.HandleFunc("GET "+i.prefix+"/jwks.json", publicJSON(i.jwksJSON))
	if i.prefix != "" {
		// The bare issuer URL is what people paste into a browser; point at discovery.
		mux.HandleFunc("GET "+i.prefix, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, i.config.Issuer+"/.well-known/openid-configuration", http.StatusFound)
		})
	}
	mux.HandleFunc("POST "+i.prefix+"/mint", i.mint)
	mux.HandleFunc("GET "+i.prefix+"/whoami", func(w http.ResponseWriter, r *http.Request) {
		subject, ok := i.subject(w, r)
		if ok {
			writeJSON(w, 200, map[string]any{"subject": subject, "audiences": i.config.Subjects[subject], "issuer": i.config.Issuer})
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { failure(w, 404, "not_found") })
	return mux
}

func (i *issuer) subject(w http.ResponseWriter, r *http.Request) (string, bool) {
	values := r.Header.Values(identityHeader)
	if len(values) != 1 || values[0] == "" {
		failure(w, 401, "authentication_required")
		return "", false
	}
	subject := values[0]
	if _, ok := i.config.Subjects[subject]; !ok {
		failure(w, 403, "subject_not_allowed")
		return "", false
	}
	return subject, true
}

type tokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	ID        string   `json:"jti"`
}

// sign produces a compact RS256 JWS (RFC 7515). The token format is fixed, so a
// dependency-free implementation is smaller and has less attack surface than a
// general JWT library; the tests verify tokens with an independent library.
func (i *issuer) sign(c tokenClaims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := i.header + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (i *issuer) mint(w http.ResponseWriter, r *http.Request) {
	subject, ok := i.subject(w, r)
	if !ok {
		return
	}
	// JSON plus a non-simple header prevent cross-origin form/fetch token issuance.
	if origin := r.Header.Get("Origin"); origin != "" && origin != i.origin {
		failure(w, 403, "origin_not_allowed")
		return
	}
	if r.Header.Get(requestHeader) != "1" {
		failure(w, 400, "X-Token-Request_header_required")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		failure(w, 415, "application_json_required")
		return
	}
	if r.URL.RawQuery != "" {
		failure(w, 400, "query_parameters_not_allowed")
		return
	}
	var request struct {
		Audience string `json:"audience"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if err := d.Decode(&request); err != nil {
		failure(w, 400, "invalid_request")
		return
	}
	if err := d.Decode(new(any)); err != io.EOF {
		failure(w, 400, "invalid_request")
		return
	}
	if !slices.Contains(i.config.Subjects[subject], request.Audience) {
		failure(w, 403, "audience_not_allowed")
		return
	}
	now := i.now()
	if ok, wait := i.limit.allow(subject, now); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
		failure(w, 429, "rate_limited")
		return
	}
	issued := now.UTC().Truncate(time.Second)
	expires := issued.Add(time.Duration(i.config.TokenLifetimeSeconds) * time.Second)
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		failure(w, 500, "token_generation_failed")
		return
	}
	claims := tokenClaims{
		Issuer: i.config.Issuer, Subject: subject, Audience: []string{request.Audience},
		IssuedAt: issued.Unix(), NotBefore: issued.Unix(), ExpiresAt: expires.Unix(),
		ID: base64.RawURLEncoding.EncodeToString(jti),
	}
	signed, err := i.sign(claims)
	if err != nil {
		failure(w, 500, "token_generation_failed")
		return
	}
	slog.Info("token minted", "subject", subject, "audience", request.Audience, "jti", claims.ID, "expires", expires)
	writeJSON(w, 200, map[string]any{"access_token": signed, "token_type": "Bearer", "expires_in": i.config.TokenLifetimeSeconds})
}

func listener(socketPath string) (net.Listener, error) {
	if os.Getenv("LISTEN_FDS") == "1" && os.Getenv("LISTEN_PID") == fmt.Sprint(os.Getpid()) {
		f := os.NewFile(3, "systemd-listener")
		defer f.Close()
		l, err := net.FileListener(f)
		if err == nil && l.Addr().Network() != "unix" {
			l.Close()
			return nil, errors.New("only Unix listeners are accepted")
		}
		return l, err
	}
	if socketPath == "" {
		return nil, errors.New("use systemd socket activation or specify -socket with a restricted Unix socket path")
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "check" {
		os.Exit(runCheck(os.Args[2:], os.Stdout, nil))
	}
	configPath := flag.String("config", "/etc/krb-jwt-issuer/config.json", "configuration path")
	socketPath := flag.String("socket", "", "Unix socket for local development; production uses systemd")
	printPublic := flag.Bool("print-public-key", false, "print the active RSA public key as PEM and exit")
	showVersion := flag.Bool("version", false, "print the version and exit (see also: \"check\" subcommand)")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	c, err := readConfig(*configPath)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	var key *rsa.PrivateKey
	if *printPublic {
		key, err = loadKey(c.PrivateKeyFile) // read-only: never generate a key as the wrong user
	} else {
		key, err = loadOrCreateKey(c.PrivateKeyFile)
	}
	if err != nil {
		slog.Error("cannot load signing key", "error", err)
		os.Exit(1)
	}
	if *printPublic {
		encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			slog.Error("cannot encode public key", "error", err)
			os.Exit(1)
		}
		_ = pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: encoded})
		return
	}
	i, err := newIssuer(c, key)
	if err != nil {
		slog.Error("cannot configure issuer", "error", err)
		os.Exit(1)
	}
	l, err := listener(*socketPath)
	if err != nil {
		slog.Error("cannot listen", "error", err)
		os.Exit(1)
	}
	server := &http.Server{Handler: i.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = server.Shutdown(shutdown)
	}()
	slog.Info("issuer ready", "version", version, "issuer", c.Issuer, "kid", i.kid)
	if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}
