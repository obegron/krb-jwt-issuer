package main

// Formal verification suite. Each test carries a requirement ID (REQ-*) that is
// traced to the specification in TESTING.md. Tests here complement main_test.go.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// mintToken mints through the real handler and returns the raw JWT.
func mintToken(t *testing.T, i *issuer, subject, audience string) string {
	t.Helper()
	w := request(i, "POST", "/issuer/mint", fmt.Sprintf(`{"audience":%q}`, audience), subject)
	if w.Code != 200 {
		t.Fatalf("mint: %d %s", w.Code, w.Body)
	}
	var r struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.TokenType != "Bearer" {
		t.Fatalf("token_type %q", r.TokenType)
	}
	return r.AccessToken
}

func decodeSegment(t *testing.T, s string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func rsaFromJWK(t *testing.T, k publicJWK) *rsa.PublicKey {
	t.Helper()
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		t.Fatal(err)
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		t.Fatal(err)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
}

// REQ-JWK-1: the kid is the RFC 7638 thumbprint. Uses the published test vector
// from RFC 7638 section 3.1.
func TestREQ_JWK_1_ThumbprintMatchesRFC7638Vector(t *testing.T) {
	const n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	nb, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jwkFor(&rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: 65537})
	if jwk.Kid != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %s", jwk.Kid)
	}
	if jwk.N != n || jwk.E != "AQAB" || jwk.Kty != "RSA" || jwk.Use != "sig" || jwk.Alg != "RS256" {
		t.Fatalf("jwk fields: %+v", jwk)
	}
}

// REQ-TOK-1: header and claim structure, exactly as specified in the README.
func TestREQ_TOK_1_TokenStructure(t *testing.T) {
	i := fixture(t)
	i.now = func() time.Time { return time.Unix(1_800_000_000, 123_456_789) }
	raw := mintToken(t, i, "alice@EXAMPLE", "test-api")
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("not a compact JWS")
	}
	h, c := decodeSegment(t, parts[0]), decodeSegment(t, parts[1])
	if h["alg"] != "RS256" || h["kid"] != i.kid || h["typ"] != "JWT" || len(h) != 3 {
		t.Fatalf("header: %v", h)
	}
	aud, ok := c["aud"].([]any)
	if !ok || len(aud) != 1 || aud[0] != "test-api" {
		t.Fatalf("aud must be a one-element array: %v", c["aud"])
	}
	want := map[string]any{"iss": i.config.Issuer, "sub": "alice@EXAMPLE", "iat": 1_800_000_000.0, "nbf": 1_800_000_000.0, "exp": 1_800_000_600.0}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("claim %s = %v, want %v", k, c[k], v)
		}
	}
	if id, _ := c["jti"].(string); len(id) != 22 { // 16 random bytes, unpadded base64url
		t.Errorf("jti %q", c["jti"])
	}
	if len(c) != 7 {
		t.Errorf("unexpected extra claims: %v", c)
	}
}

// REQ-TOK-2: each token has a unique jti, including under concurrency.
func TestREQ_TOK_2_JTIUniqueUnderConcurrency(t *testing.T) {
	i := fixture(t)
	var mu sync.Mutex
	seen := map[string]bool{}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 25; n++ {
				raw := mintToken(t, i, "alice@EXAMPLE", "test-api")
				id := decodeSegment(t, strings.Split(raw, ".")[1])["jti"].(string)
				mu.Lock()
				if seen[id] {
					t.Errorf("duplicate jti %s", id)
				}
				seen[id] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != 200 {
		t.Fatal(len(seen))
	}
}

// REQ-TOK-3: lifetime follows configuration at both bounds.
func TestREQ_TOK_3_ConfiguredLifetimeHonoured(t *testing.T) {
	for _, secs := range []int{30, 900} {
		i := fixture(t)
		i.config.TokenLifetimeSeconds = secs
		raw := mintToken(t, i, "alice@EXAMPLE", "test-api")
		c := decodeSegment(t, strings.Split(raw, ".")[1])
		if got := int(c["exp"].(float64) - c["iat"].(float64)); got != secs {
			t.Errorf("lifetime %d, want %d", got, secs)
		}
	}
}

// REQ-TOK-4: a verifier that pins RS256 rejects alg=none, HS256 key confusion
// (public key used as HMAC secret) and a token signed by a foreign key.
func TestREQ_TOK_4_AlgorithmConfusionRejected(t *testing.T) {
	i := fixture(t)
	pub := &i.key.PublicKey
	claims := jwt.RegisteredClaims{Issuer: i.config.Issuer, Subject: "alice@EXAMPLE", Audience: jwt.ClaimStrings{"test-api"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}
	verify := func(raw string) error {
		_, err := jwt.ParseWithClaims(raw, &jwt.RegisteredClaims{}, func(*jwt.Token) (any, error) { return pub, nil },
			jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(i.config.Issuer), jwt.WithAudience("test-api"), jwt.WithExpirationRequired())
		return err
	}
	if err := verify(mintToken(t, i, "alice@EXAMPLE", "test-api")); err != nil {
		t.Fatalf("control token rejected: %v", err)
	}
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	hs, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(pubDER)
	foreign, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(foreign)
	for name, raw := range map[string]string{"alg none": none, "HS256 confusion": hs, "foreign key": other} {
		if verify(raw) == nil {
			t.Errorf("%s token accepted", name)
		}
	}
}

// REQ-TOK-5: the token binds to the exact requested audience and never to a
// near-match (case, whitespace, prefix).
func TestREQ_TOK_5_AudienceMatchingIsExact(t *testing.T) {
	i := fixture(t)
	for _, aud := range []string{"TEST-API", " test-api", "test-api ", "test-ap", "test-api\u0000", "", "*"} {
		body, _ := json.Marshal(map[string]string{"audience": aud})
		if w := request(i, "POST", "/issuer/mint", string(body), "alice@EXAMPLE"); w.Code != 403 {
			t.Errorf("audience %q -> %d", aud, w.Code)
		}
	}
	// Wrong JSON types and missing field must not mint.
	for _, body := range []string{`{}`, `{"audience":null}`, `{"audience":["test-api"]}`, `{"audience":1}`, ``, `null`, `[]`, `"test-api"`} {
		if w := request(i, "POST", "/issuer/mint", body, "alice@EXAMPLE"); w.Code == 200 {
			t.Errorf("body %q minted", body)
		}
	}
}

// REQ-AUTHZ-1: a subject only receives audiences configured for that subject.
func TestREQ_AUTHZ_1_PerSubjectAudienceIsolation(t *testing.T) {
	i := fixture(t)
	i.config.Subjects = map[string][]string{"alice@EXAMPLE": {"a-api"}, "bob@EXAMPLE": {"b-api", "c-api"}}
	cases := []struct {
		sub, aud string
		code     int
	}{
		{"alice@EXAMPLE", "a-api", 200}, {"alice@EXAMPLE", "b-api", 403},
		{"bob@EXAMPLE", "b-api", 200}, {"bob@EXAMPLE", "c-api", 200}, {"bob@EXAMPLE", "a-api", 403},
		{"alice@example", "a-api", 403}, // principal comparison is case-sensitive
		{"alice@EXAMPLE ", "a-api", 403},
	}
	for _, tc := range cases {
		w := request(i, "POST", "/issuer/mint", fmt.Sprintf(`{"audience":%q}`, tc.aud), tc.sub)
		if w.Code != tc.code {
			t.Errorf("%q/%q: %d want %d", tc.sub, tc.aud, w.Code, tc.code)
		}
	}
}

// REQ-HTTP-1: request-shape controls on /mint.
func TestREQ_HTTP_1_MintRequestControls(t *testing.T) {
	i := fixture(t)
	do := func(mutate func(*http.Request), path string) int {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"audience":"test-api"}`))
		r.Header.Set(identityHeader, "alice@EXAMPLE")
		r.Header.Set(requestHeader, "1")
		r.Header.Set("Content-Type", "application/json")
		if mutate != nil {
			mutate(r)
		}
		w := httptest.NewRecorder()
		i.handler().ServeHTTP(w, r)
		return w.Code
	}
	checks := []struct {
		name   string
		mutate func(*http.Request)
		path   string
		code   int
	}{
		{"baseline", nil, "/issuer/mint", 200},
		{"same origin allowed", func(r *http.Request) { r.Header.Set("Origin", "https://auth.example") }, "/issuer/mint", 200},
		{"origin null rejected", func(r *http.Request) { r.Header.Set("Origin", "null") }, "/issuer/mint", 403},
		{"origin wrong scheme", func(r *http.Request) { r.Header.Set("Origin", "http://auth.example") }, "/issuer/mint", 403},
		{"origin subdomain", func(r *http.Request) { r.Header.Set("Origin", "https://evil.auth.example") }, "/issuer/mint", 403},
		{"origin with port", func(r *http.Request) { r.Header.Set("Origin", "https://auth.example:8443") }, "/issuer/mint", 403},
		{"charset param ok", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, "/issuer/mint", 200},
		{"text/plain rejected", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, "/issuer/mint", 415},
		{"multipart rejected", func(r *http.Request) { r.Header.Set("Content-Type", "multipart/form-data; boundary=x") }, "/issuer/mint", 415},
		{"no content type", func(r *http.Request) { r.Header.Del("Content-Type") }, "/issuer/mint", 415},
		{"csrf header wrong value", func(r *http.Request) { r.Header.Set(requestHeader, "0") }, "/issuer/mint", 400},
		{"query string rejected", nil, "/issuer/mint?audience=test-api", 400},
		{"empty identity", func(r *http.Request) { r.Header.Set(identityHeader, "") }, "/issuer/mint", 401},
		{"trailing slash is not the endpoint", nil, "/issuer/mint/", 404},
		{"path outside issuer prefix", nil, "/mint", 404},
		{"path traversal is redirected to the cleaned path, never served", nil, "/issuer/../mint", 307},
	}
	for _, c := range checks {
		if got := do(c.mutate, c.path); got != c.code {
			t.Errorf("%s: got %d want %d", c.name, got, c.code)
		}
	}
}

// REQ-HTTP-2: only the documented method is accepted per endpoint, and no
// request ever mints a token without POST.
func TestREQ_HTTP_2_MethodsAndNoTokenLeak(t *testing.T) {
	i := fixture(t)
	for _, m := range []string{"GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} {
		w := request(i, m, "/issuer/mint", `{"audience":"test-api"}`, "alice@EXAMPLE")
		if w.Code == 200 || strings.Contains(w.Body.String(), "access_token") {
			t.Errorf("%s /mint returned %d", m, w.Code)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		for _, p := range []string{"/issuer/jwks.json", "/issuer/.well-known/openid-configuration", "/issuer/whoami"} {
			if w := request(i, m, p, "{}", "alice@EXAMPLE"); w.Code == 200 {
				t.Errorf("%s %s accepted", m, p)
			}
		}
	}
}

// REQ-HTTP-3: every response carries safe headers, including errors and 404.
// Dynamic responses are no-store; the two immutable public documents may be
// cached for at most five minutes. No CORS headers anywhere.
func TestREQ_HTTP_3_ResponseHeaders(t *testing.T) {
	i := fixture(t)
	for _, c := range []struct {
		method, path, subject, cache string
	}{
		{"GET", "/issuer/jwks.json", "", "public, max-age=300"}, {"GET", "/issuer/.well-known/openid-configuration", "", "public, max-age=300"},
		{"GET", "/issuer/whoami", "alice@EXAMPLE", "no-store"}, {"GET", "/issuer/whoami", "", "no-store"}, {"GET", "/healthz", "", "no-store"},
		{"POST", "/issuer/mint", "alice@EXAMPLE", "no-store"}, {"GET", "/nothing", "", "no-store"},
	} {
		w := request(i, c.method, c.path, `{"audience":"test-api"}`, c.subject)
		h := w.Header()
		if h.Get("Content-Type") != "application/json" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != c.cache {
			t.Errorf("%s %s: headers %v", c.method, c.path, h)
		}
		if h.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s %s: CORS must not be enabled", c.method, c.path)
		}
	}
}

// REQ-HTTP-5: the bare issuer URL redirects to discovery, and only exactly
// that URL. Nothing is served at the bare URL when the issuer has no path.
func TestREQ_HTTP_5_IssuerRootRedirectsToDiscovery(t *testing.T) {
	i := fixture(t)
	w := request(i, "GET", "/issuer", "", "")
	if w.Code != 302 || w.Header().Get("Location") != i.config.Issuer+"/.well-known/openid-configuration" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if strings.Contains(w.Body.String(), "access_token") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("redirect must be inert and uncached")
	}
	for _, p := range []string{"/issuer/", "/issuerx", "/issuer/x"} {
		if w := request(i, "GET", p, "", ""); w.Code == 302 || w.Code == 200 {
			t.Errorf("%s -> %d", p, w.Code)
		}
	}
	if w := request(i, "POST", "/issuer", `{"audience":"test-api"}`, "alice@EXAMPLE"); w.Code == 200 || w.Code == 302 {
		t.Errorf("POST /issuer -> %d", w.Code)
	}
}

// REQ-RATE-1: per-subject token bucket: burst, 429 with Retry-After, refill
// over time, and isolation between subjects.
func TestREQ_RATE_1_MintRateLimit(t *testing.T) {
	i := fixture(t)
	i.config.Subjects["bob@EXAMPLE"] = []string{"test-api"}
	i.limit = newLimiter(mintRatePerSecond, mintBurst)
	clock := time.Unix(1_800_000_000, 0)
	i.now = func() time.Time { return clock }
	mint := func(sub string) *httptest.ResponseRecorder {
		return request(i, "POST", "/issuer/mint", `{"audience":"test-api"}`, sub)
	}
	for n := 0; n < mintBurst; n++ {
		if w := mint("alice@EXAMPLE"); w.Code != 200 {
			t.Fatalf("burst request %d: %d", n, w.Code)
		}
	}
	w := mint("alice@EXAMPLE")
	if w.Code != 429 || w.Header().Get("Retry-After") != "2" || strings.Contains(w.Body.String(), "access_token") {
		t.Fatalf("over burst: %d %v %s", w.Code, w.Header(), w.Body)
	}
	if w := mint("bob@EXAMPLE"); w.Code != 200 {
		t.Fatalf("another subject was throttled: %d", w.Code)
	}
	clock = clock.Add(1 * time.Second) // 0.5 token: not enough
	if w := mint("alice@EXAMPLE"); w.Code != 429 {
		t.Fatalf("early retry: %d", w.Code)
	}
	clock = clock.Add(1 * time.Second) // one full token
	if w := mint("alice@EXAMPLE"); w.Code != 200 {
		t.Fatalf("after refill: %d", w.Code)
	}
	if w := mint("alice@EXAMPLE"); w.Code != 429 {
		t.Fatalf("refill granted more than one token: %d", w.Code)
	}
	clock = clock.Add(time.Hour) // long idle must cap at the burst size
	ok := 0
	for n := 0; n < 20; n++ {
		if mint("alice@EXAMPLE").Code == 200 {
			ok++
		}
	}
	if ok != mintBurst {
		t.Fatalf("burst after idle = %d, want %d", ok, mintBurst)
	}
	// Rejected requests (bad audience, unauthenticated) must not consume tokens
	// or create limiter state for unknown subjects.
	before := len(i.limit.buckets)
	request(i, "POST", "/issuer/mint", `{"audience":"nope"}`, "alice@EXAMPLE")
	request(i, "POST", "/issuer/mint", `{"audience":"test-api"}`, "mallory@EXAMPLE")
	request(i, "POST", "/issuer/mint", `{"audience":"test-api"}`, "")
	if len(i.limit.buckets) != before {
		t.Fatal("limiter state grew for rejected requests")
	}
}

// REQ-HTTP-4: /whoami reports identity only for a configured subject, and
// error responses never echo the client-supplied identity.
func TestREQ_HTTP_4_Whoami(t *testing.T) {
	i := fixture(t)
	w := request(i, "GET", "/issuer/whoami", "", "alice@EXAMPLE")
	var got struct {
		Subject   string   `json:"subject"`
		Audiences []string `json:"audiences"`
		Issuer    string   `json:"issuer"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 {
		t.Fatal(w.Code, err)
	}
	if got.Subject != "alice@EXAMPLE" || len(got.Audiences) != 1 || got.Audiences[0] != "test-api" || got.Issuer != i.config.Issuer {
		t.Fatalf("%+v", got)
	}
	if w := request(i, "GET", "/issuer/whoami", "", "mallory<script>@EXAMPLE"); w.Code != 403 || strings.Contains(w.Body.String(), "mallory") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := request(i, "GET", "/issuer/whoami", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
}

// REQ-DISC-1: discovery is consistent with the JWKS and issuer; the issuer in
// the document must equal the configured issuer byte for byte, including when
// the issuer has no path component.
func TestREQ_DISC_1_DiscoveryConsistency(t *testing.T) {
	for _, iss := range []string{"https://auth.example/issuer", "https://auth.example", "https://auth.example/a/b"} {
		i := fixture(t)
		i.config.Issuer = iss
		i2, err := newIssuer(i.config, i.key)
		if err != nil {
			t.Fatal(iss, err)
		}
		w := request(i2, "GET", i2.prefix+"/.well-known/openid-configuration", "", "")
		var d struct {
			Issuer  string   `json:"issuer"`
			JWKSURI string   `json:"jwks_uri"`
			Algs    []string `json:"id_token_signing_alg_values_supported"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 {
			t.Fatal(iss, w.Code, err)
		}
		if d.Issuer != iss || d.JWKSURI != iss+"/jwks.json" || len(d.Algs) != 1 || d.Algs[0] != "RS256" {
			t.Errorf("%s: %+v", iss, d)
		}
		// The advertised jwks_uri must resolve on this very handler.
		if w := request(i2, "GET", strings.TrimPrefix(d.JWKSURI, "https://auth.example"), "", ""); w.Code != 200 {
			t.Errorf("%s: jwks_uri not served (%d)", iss, w.Code)
		}
	}
}

// REQ-JWK-2: JWKS never exposes private RSA members, and each key is a
// complete public JWK.
func TestREQ_JWK_2_JWKSPublicOnly(t *testing.T) {
	i := fixture(t)
	w := request(i, "GET", "/issuer/jwks.json", "", "")
	var raw struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil || len(raw.Keys) != 1 {
		t.Fatal(err, w.Body)
	}
	for _, f := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := raw.Keys[0][f]; ok {
			t.Errorf("private member %q published", f)
		}
	}
	for _, f := range []string{"kty", "use", "alg", "kid", "n", "e"} {
		if raw.Keys[0][f] == nil || raw.Keys[0][f] == "" {
			t.Errorf("missing %q", f)
		}
	}
}

func writePublicPEM(t *testing.T, dir, name string, pub any) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
}

// REQ-KEY-1: after rotation, tokens signed by the old key still verify against
// the published JWKS, new tokens use the new kid, and kids are distinct.
func TestREQ_KEY_1_RotationOverlapVerifiesOldTokens(t *testing.T) {
	old := fixture(t)
	oldToken := mintToken(t, old, "alice@EXAMPLE", "test-api")

	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	dir := t.TempDir()
	writePublicPEM(t, dir, "old.pem", &old.key.PublicKey)
	writePublicPEM(t, dir, "dup-of-old.pem", &old.key.PublicKey) // duplicates must collapse
	c := old.config
	c.PreviousPublicKeysDir = dir
	rotated, err := newIssuer(c, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated.jwks) != 2 || rotated.jwks[0].Kid == rotated.jwks[1].Kid {
		t.Fatalf("jwks: %+v", rotated.jwks)
	}
	if rotated.jwks[0].Kid != rotated.kid {
		t.Fatal("active key must be listed first")
	}
	byKid := map[string]*rsa.PublicKey{}
	for _, k := range rotated.jwks {
		byKid[k.Kid] = rsaFromJWK(t, k)
	}
	verify := func(raw string) (string, error) {
		var used string
		_, err := jwt.ParseWithClaims(raw, &jwt.RegisteredClaims{}, func(tok *jwt.Token) (any, error) {
			used, _ = tok.Header["kid"].(string)
			if k := byKid[used]; k != nil {
				return k, nil
			}
			return nil, fmt.Errorf("unknown kid %q", used)
		}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience("test-api"))
		return used, err
	}
	if kid, err := verify(oldToken); err != nil || kid != old.kid {
		t.Fatalf("old token after rotation: %v (kid %s)", err, kid)
	}
	newToken := mintToken(t, rotated, "alice@EXAMPLE", "test-api")
	if kid, err := verify(newToken); err != nil || kid != rotated.kid || kid == old.kid {
		t.Fatalf("new token: %v (kid %s)", err, kid)
	}
	// Active key listed in the previous directory must not be duplicated.
	writePublicPEM(t, dir, "self.pem", &newKey.PublicKey)
	if again, err := newIssuer(c, newKey); err != nil || len(again.jwks) != 2 {
		t.Fatalf("active key duplicated: %v %d", err, len(again.jwks))
	}
}

// REQ-KEY-2: a malformed previous-key directory prevents startup rather than
// being skipped silently, and never leaks private keys into JWKS.
func TestREQ_KEY_2_PreviousKeyValidation(t *testing.T) {
	good := fixture(t)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	cases := map[string][]byte{
		"private key PEM": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		"not PEM":         []byte("hello"),
		"empty":           {},
		"garbage DER":     pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}}),
		"RSA PUBLIC KEY":  pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: []byte{1}}),
	}
	smallDER, _ := x509.MarshalPKIXPublicKey(&small.PublicKey)
	cases["1024-bit key"] = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: smallDER})
	for name, data := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "k.pem"), data, 0600); err != nil {
			t.Fatal(err)
		}
		c := good.config
		c.PreviousPublicKeysDir = dir
		if _, err := newIssuer(c, good.key); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Non-.pem files and a missing directory are ignored.
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0600)
	c := good.config
	c.PreviousPublicKeysDir = dir
	if i, err := newIssuer(c, good.key); err != nil || len(i.jwks) != 1 {
		t.Fatal(err)
	}
	c.PreviousPublicKeysDir = filepath.Join(dir, "does-not-exist")
	if i, err := newIssuer(c, good.key); err != nil || len(i.jwks) != 1 {
		t.Fatal(err)
	}
}

// REQ-KEY-3: startup key loading is fail-closed.
func TestREQ_KEY_3_KeyLoadingFailsClosed(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := loadOrCreateKey(write("garbage.pem", []byte("not a key"), 0600)); err == nil {
		t.Error("garbage key accepted")
	}
	if _, err := loadOrCreateKey(write("empty.pem", nil, 0600)); err == nil {
		t.Error("empty key file silently replaced or accepted")
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := x509.MarshalPKCS8PrivateKey(weak)
	if _, err := loadOrCreateKey(write("weak.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)); err == nil {
		t.Error("1024-bit key accepted")
	}
	target := write("target.pem", []byte("x"), 0600)
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKey(link); err == nil {
		t.Error("symlinked key accepted")
	}
	if _, err := loadOrCreateKey(dir); err == nil {
		t.Error("directory accepted as key")
	}
	// Group-readable and other-readable are both refused.
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	kder, _ := x509.MarshalPKCS8PrivateKey(k)
	kpem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	for _, mode := range []os.FileMode{0640, 0604, 0660, 0666} {
		p := write(fmt.Sprintf("mode%o.pem", mode), kpem, mode)
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreateKey(p); err == nil {
			t.Errorf("mode %o accepted", mode)
		}
	}
	// A rejected key must be left intact, never overwritten.
	p := write("keep.pem", []byte("precious"), 0644)
	_, _ = loadOrCreateKey(p)
	if b, _ := os.ReadFile(p); string(b) != "precious" {
		t.Error("rejected key file was modified")
	}
	// PKCS#1 keys are accepted as well as PKCS#8, and 0400 is allowed.
	p1 := write("pkcs1.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0400)
	if loaded, err := loadOrCreateKey(p1); err != nil || loaded.N.Cmp(k.N) != 0 {
		t.Errorf("pkcs1 key: %v", err)
	}
}

// REQ-KEY-5: key creation is atomic and read-only loading never creates.
func TestREQ_KEY_5_AtomicCreationAndReadOnlyLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("3072-bit generation")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key.pem")
	if _, err := loadKey(path); err == nil {
		t.Fatal("loadKey must fail on a missing key")
	}
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("loadKey created a file")
	}
	// A stale temp file from an interrupted start is replaced, not trusted.
	if err := os.WriteFile(path+".tmp", []byte("half-written"), 0600); err != nil {
		t.Fatal(err)
	}
	k, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	loaded, err := loadKey(path)
	if err != nil || loaded.N.Cmp(k.N) != 0 {
		t.Fatal("created key does not load")
	}
	// createKey must never replace an existing key, even if called directly.
	before, _ := os.ReadFile(path)
	if _, err := createKey(path); err == nil {
		t.Fatal("createKey replaced an existing key")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("existing key modified")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("failed creation left files: %v", entries)
	}
}

// REQ-KEY-4: first start generates a 3072-bit key in a 0700 directory with a
// 0600 file, and a pre-existing directory is not re-permissioned.
func TestREQ_KEY_4_GeneratedKeyProperties(t *testing.T) {
	if testing.Short() {
		t.Skip("3072-bit generation")
	}
	path := filepath.Join(t.TempDir(), "nested", "state", "signing.key.pem")
	k, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if k.N.BitLen() != 3072 {
		t.Errorf("key size %d", k.N.BitLen())
	}
	if di, _ := os.Stat(filepath.Dir(path)); di.Mode().Perm() != 0700 {
		t.Errorf("dir mode %o", di.Mode().Perm())
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Errorf("file mode %o", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "-----BEGIN PRIVATE KEY-----") {
		t.Error("expected PKCS#8 PEM")
	}
}

// REQ-CFG-1: configuration validation, table-driven.
func TestREQ_CFG_1_ValidationTable(t *testing.T) {
	base := fixture(t).config
	mut := func(f func(*config)) config {
		c := base
		c.Subjects = map[string][]string{"a@X": {"api"}}
		f(&c)
		return c
	}
	bad := map[string]config{
		"http issuer":           mut(func(c *config) { c.Issuer = "http://auth.example/issuer" }),
		"empty issuer":          mut(func(c *config) { c.Issuer = "" }),
		"no host":               mut(func(c *config) { c.Issuer = "https:///issuer" }),
		"trailing slash":        mut(func(c *config) { c.Issuer = "https://auth.example/" }),
		"fragment":              mut(func(c *config) { c.Issuer = "https://auth.example/i#f" }),
		"query":                 mut(func(c *config) { c.Issuer = "https://auth.example/i?x" }),
		"userinfo":              mut(func(c *config) { c.Issuer = "https://u@auth.example/i" }),
		"double slash":          mut(func(c *config) { c.Issuer = "https://auth.example//i" }),
		"encoded path":          mut(func(c *config) { c.Issuer = "https://auth.example/a%2Fb" }),
		"relative key path":     mut(func(c *config) { c.PrivateKeyFile = "key.pem" }),
		"empty key path":        mut(func(c *config) { c.PrivateKeyFile = "" }),
		"lifetime 29":           mut(func(c *config) { c.TokenLifetimeSeconds = 29 }),
		"lifetime 901":          mut(func(c *config) { c.TokenLifetimeSeconds = 901 }),
		"lifetime 0":            mut(func(c *config) { c.TokenLifetimeSeconds = 0 }),
		"lifetime negative":     mut(func(c *config) { c.TokenLifetimeSeconds = -1 }),
		"no subjects":           mut(func(c *config) { c.Subjects = nil }),
		"empty subject":         mut(func(c *config) { c.Subjects = map[string][]string{"": {"api"}} }),
		"padded subject":        mut(func(c *config) { c.Subjects = map[string][]string{" a@X": {"api"}} }),
		"subject w/o audiences": mut(func(c *config) { c.Subjects = map[string][]string{"a@X": {}} }),
		"wildcard audience":     mut(func(c *config) { c.Subjects = map[string][]string{"a@X": {"*"}} }),
		"empty audience":        mut(func(c *config) { c.Subjects = map[string][]string{"a@X": {""}} }),
		"padded audience":       mut(func(c *config) { c.Subjects = map[string][]string{"a@X": {"api "}} }),
		"one bad among good":    mut(func(c *config) { c.Subjects = map[string][]string{"a@X": {"api"}, "b@X": {"*"}} }),
	}
	for name, c := range bad {
		if c.validate() == nil {
			t.Errorf("%s accepted", name)
		}
		if _, err := newIssuer(c, fixture(t).key); err == nil {
			t.Errorf("%s: newIssuer accepted invalid config", name)
		}
	}
	for _, ok := range []func(*config){
		func(c *config) {}, func(c *config) { c.TokenLifetimeSeconds = 30 }, func(c *config) { c.TokenLifetimeSeconds = 900 },
		func(c *config) { c.Issuer = "https://auth.example" }, func(c *config) { c.Issuer = "https://auth.example:8443/a/b" },
	} {
		if err := mut(ok).validate(); err != nil {
			t.Errorf("valid config rejected: %v", err)
		}
	}
}

// REQ-CFG-2: strict config file parsing.
func TestREQ_CFG_2_ReadConfigStrict(t *testing.T) {
	dir := t.TempDir()
	valid := `{"issuer":"https://auth.example/issuer","private_key_file":"/var/lib/x/k.pem","token_lifetime_seconds":600,"subjects":{"a@X":["api"]}}`
	write := func(s string) string {
		p := filepath.Join(dir, fmt.Sprintf("c%d.json", time.Now().UnixNano()))
		if err := os.WriteFile(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if c, err := readConfig(write(valid)); err != nil || c.Issuer != "https://auth.example/issuer" {
		t.Fatalf("valid config: %v", err)
	}
	// The shipped example must always remain valid.
	if _, err := readConfig("config.example.json"); err != nil {
		t.Errorf("config.example.json invalid: %v", err)
	}
	bad := map[string]string{
		"unknown field":   strings.Replace(valid, `"subjects"`, `"admin":true,"subjects"`, 1),
		"trailing object": valid + `{}`,
		"trailing text":   valid + ` junk`,
		"empty":           ``,
		"array":           `[]`,
		"truncated":       valid[:len(valid)-3],
		"wrong type":      strings.Replace(valid, `600`, `"600"`, 1),
		"oversize":        `{"issuer":"` + strings.Repeat("a", 70000) + `"}`,
	}
	for name, s := range bad {
		if _, err := readConfig(write(s)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := readConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file accepted")
	}
}

// REQ-NET-1: the server only binds to Unix sockets, with owner-only mode.
func TestREQ_NET_1_UnixSocketOnly(t *testing.T) {
	t.Setenv("LISTEN_FDS", "")
	if _, err := listener(""); err == nil {
		t.Error("no socket and no activation must be an error")
	}
	// /tmp-style short path to stay under sun_path limits.
	dir, err := os.MkdirTemp("", "hi")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	l, err := listener(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.Addr().Network() != "unix" {
		t.Error("not a unix listener")
	}
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0600 {
		t.Errorf("socket mode %o", fi.Mode().Perm())
	}
	// Serve over the socket end-to-end through a real HTTP stack.
	i := fixture(t)
	srv := &http.Server{Handler: i.handler()}
	go srv.Serve(l)
	defer srv.Close()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET /issuer/jwks.json HTTP/1.1\r\nHost: auth.example\r\nConnection: close\r\n\r\n")
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 200") || !strings.Contains(string(buf[:n]), `"keys"`) {
		t.Errorf("unexpected response: %q", buf[:n])
	}
}

// REQ-OBS-1: logs record the mint but never the bearer token or key material.
func TestREQ_OBS_1_LogsContainNoSecrets(t *testing.T) {
	var buf strings.Builder
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)
	i := fixture(t)
	raw := mintToken(t, i, "alice@EXAMPLE", "test-api")
	out := buf.String()
	if !strings.Contains(out, "token minted") || !strings.Contains(out, "alice@EXAMPLE") {
		t.Errorf("mint not logged: %q", out)
	}
	if strings.Contains(out, raw) || strings.Contains(out, strings.Split(raw, ".")[2]) || strings.Contains(out, "PRIVATE") {
		t.Error("secret material in log")
	}
}

// REQ-ROB-1: the mint decoder never panics or mints on arbitrary input.
func FuzzMintBody(f *testing.F) {
	for _, s := range []string{`{"audience":"test-api"}`, `{}`, `{"audience":`, `null`, "\x00", `{"audience":"test-api","audience":"x"}`, `{"Audience":"test-api"}`} {
		f.Add(s)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	i, err := newIssuer(config{Issuer: "https://auth.example/issuer", PrivateKeyFile: "/k", TokenLifetimeSeconds: 600, Subjects: map[string][]string{"alice@EXAMPLE": {"test-api"}}}, key)
	if err != nil {
		f.Fatal(err)
	}
	i.limit = newLimiter(1e9, 1e9)
	f.Fuzz(func(t *testing.T, body string) {
		w := request(i, "POST", "/issuer/mint", body, "alice@EXAMPLE")
		if w.Code == 200 {
			var req struct {
				Audience string `json:"audience"`
			}
			// A token may only be issued if the body is a strict JSON object whose
			// single field resolves to the permitted audience.
			if err := json.Unmarshal([]byte(body), &req); err != nil || req.Audience != "test-api" {
				t.Fatalf("minted for body %q", body)
			}
		}
		if w.Code >= 500 {
			t.Fatalf("server error %d for %q", w.Code, body)
		}
	})
}

// REQ-ROB-2: a fuzz-style sweep of identity header values.
func TestREQ_ROB_2_IdentityHeaderValues(t *testing.T) {
	i := fixture(t)
	for _, v := range []string{"alice@EXAMPLE\r\nX-Evil: 1", "alice@EXAMPLE,mallory@EXAMPLE", "ALICE@EXAMPLE", "alice@EXAMPLE\t", "alice", "@EXAMPLE", strings.Repeat("a", 10000)} {
		r := httptest.NewRequest("POST", "/issuer/mint", strings.NewReader(`{"audience":"test-api"}`))
		r.Header["X-Authenticated-Principal"] = []string{v}
		r.Header.Set(requestHeader, "1")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		i.handler().ServeHTTP(w, r)
		if w.Code == 200 {
			t.Errorf("identity %q minted", v)
		}
	}
	// Header-name case variants collapse to a single canonical header (nginx
	// overwrites it); a client cannot smuggle a second value through case.
	r := httptest.NewRequest("POST", "/issuer/mint", strings.NewReader(`{"audience":"test-api"}`))
	r.Header.Set("x-authenticated-principal", "alice@EXAMPLE")
	r.Header.Add("X-AUTHENTICATED-PRINCIPAL", "mallory@EXAMPLE")
	r.Header.Set(requestHeader, "1")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	i.handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("duplicate identity headers: %d", w.Code)
	}
}
