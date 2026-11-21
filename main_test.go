package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func fixture(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := config{Issuer: "https://auth.example/issuer", PrivateKeyFile: filepath.Join(t.TempDir(), "key.pem"), TokenLifetimeSeconds: 600, Subjects: map[string][]string{"alice@EXAMPLE": {"test-api"}}}
	i, err := newIssuer(c, key)
	if err != nil {
		t.Fatal(err)
	}
	i.limit = newLimiter(1e6, 1e6) // tests mint in bulk; the limiter has its own tests
	return i
}

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

func request(i *issuer, method, path, body, subject string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if subject != "" {
		r.Header.Set(identityHeader, subject)
	}
	r.Header.Set(requestHeader, "1")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	i.handler().ServeHTTP(w, r)
	return w
}

func TestMintAndVerifyWithPublishedKey(t *testing.T) {
	i := fixture(t)
	w := request(i, "POST", "/issuer/mint", `{"audience":"test-api"}`, "alice@EXAMPLE")
	if w.Code != 200 {
		t.Fatalf("mint: %d %s", w.Code, w.Body)
	}
	var response struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ExpiresIn != 600 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("lifetime/cache policy")
	}
	jwks := request(i, "GET", "/issuer/jwks.json", "", "")
	var published struct {
		Keys []publicJWK `json:"keys"`
	}
	if err := json.Unmarshal(jwks.Body.Bytes(), &published); err != nil {
		t.Fatal(err)
	}
	jwk := published.Keys[0]
	n, _ := base64.RawURLEncoding.DecodeString(jwk.N)
	e, _ := base64.RawURLEncoding.DecodeString(jwk.E)
	public := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	parse := func(raw, audience string, now time.Time) (*jwt.Token, error) {
		return jwt.ParseWithClaims(raw, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
			if token.Header["kid"] != jwk.Kid {
				t.Error("unexpected signing key")
			}
			return public, nil
		}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(i.config.Issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now }))
	}
	token, err := parse(response.AccessToken, "test-api", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(*jwt.RegisteredClaims)
	if claims.Subject != "alice@EXAMPLE" || claims.ID == "" || claims.ExpiresAt.Sub(claims.IssuedAt.Time) != 10*time.Minute {
		t.Fatal("incorrect claims")
	}
	if _, err := parse(response.AccessToken, "other-api", time.Now()); err == nil {
		t.Fatal("wrong audience accepted")
	}
	if _, err := parse(response.AccessToken, "test-api", time.Now().Add(11*time.Minute)); err == nil {
		t.Fatal("expired token accepted")
	}
	parts := strings.Split(response.AccessToken, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(strings.ReplaceAll(string(payload), "alice", "admin")))
	if _, err := parse(strings.Join(parts, "."), "test-api", time.Now()); err == nil {
		t.Fatal("tampered token accepted")
	}
	if strings.Contains(jwks.Body.String(), `"d"`) || strings.Contains(jwks.Body.String(), "PRIVATE") {
		t.Fatal("private key leaked")
	}
}

func TestMintRejectsUntrustedRequests(t *testing.T) {
	i := fixture(t)
	cases := []struct {
		name, subject, body string
		mutate              func(*http.Request)
		code                int
	}{
		{"anonymous", "", `{"audience":"test-api"}`, nil, 401},
		{"other subject", "mallory@EXAMPLE", `{"audience":"test-api"}`, nil, 403},
		{"other audience", "alice@EXAMPLE", `{"audience":"admin-api"}`, nil, 403},
		{"claims injection", "alice@EXAMPLE", `{"audience":"test-api","sub":"root"}`, nil, 400},
		{"trailing JSON", "alice@EXAMPLE", `{"audience":"test-api"} {}`, nil, 400},
		{"oversized body", "alice@EXAMPLE", `{"audience":"` + strings.Repeat("x", 5000) + `"}`, nil, 400},
		{"foreign origin", "alice@EXAMPLE", `{"audience":"test-api"}`, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403},
		{"missing CSRF header", "alice@EXAMPLE", `{"audience":"test-api"}`, func(r *http.Request) { r.Header.Del(requestHeader) }, 400},
		{"form request", "alice@EXAMPLE", `audience=test-api`, func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, 415},
		{"ambiguous identity", "alice@EXAMPLE", `{"audience":"test-api"}`, func(r *http.Request) { r.Header.Add(identityHeader, "mallory@EXAMPLE") }, 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/issuer/mint", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set(requestHeader, "1")
			if tc.subject != "" {
				r.Header.Set(identityHeader, tc.subject)
			}
			if tc.mutate != nil {
				tc.mutate(r)
			}
			w := httptest.NewRecorder()
			i.handler().ServeHTTP(w, r)
			if w.Code != tc.code {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.code, w.Body)
			}
		})
	}
	if w := request(i, "GET", "/issuer/mint", "", "alice@EXAMPLE"); w.Code == 200 {
		t.Fatal("GET minted a token")
	}
}

func TestDiscoveryDoesNotClaimUnsupportedFlows(t *testing.T) {
	i := fixture(t)
	w := request(i, "GET", "/issuer/.well-known/openid-configuration", "", "")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var data map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if data["issuer"] != i.config.Issuer || data["jwks_uri"] != i.config.Issuer+"/jwks.json" {
		t.Fatal(data)
	}
	if data["authorization_endpoint"] != nil || data["token_endpoint"] != nil {
		t.Fatal("advertising unsupported OAuth endpoints")
	}
}

func TestKeyPersistsAndRotationRetainsPublicKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key.pem")
	key, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if key.N.Cmp(loaded.N) != 0 {
		t.Fatal("key changed after reload")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("key permissions")
	}
	i := fixture(t)
	i.config.PreviousPublicKeysDir = t.TempDir()
	encoded, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err := os.WriteFile(filepath.Join(i.config.PreviousPublicKeysDir, "old.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	rotated, err := newIssuer(i.config, i.key)
	if err != nil || len(rotated.jwks) != 2 {
		t.Fatal("rotation public-key overlap failed", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKey(path); err == nil {
		t.Fatal("world-readable signing key accepted")
	}
}

func TestInvalidConfiguration(t *testing.T) {
	i := fixture(t)
	for _, value := range []string{"http://auth.example/issuer", "https://auth.example/issuer/", "https://user:pass@auth.example/issuer", "https://auth.example/issuer?x=y"} {
		c := i.config
		c.Issuer = value
		if c.validate() == nil {
			t.Fatal("accepted invalid issuer", value)
		}
	}
	c := i.config
	c.TokenLifetimeSeconds = 86400
	if c.validate() == nil {
		t.Fatal("accepted excessive lifetime")
	}
}
