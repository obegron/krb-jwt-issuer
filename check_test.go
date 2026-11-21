package main

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeNginx stands in for the real front end so the self-check can be tested
// without Kerberos. Each flag reproduces one realistic misconfiguration.
type fakeNginx struct {
	i             *issuer
	principal     string
	noAuth        bool // auth_gss not enabled on protected locations
	trustClient   bool // passes the client's identity header through when anonymous
	noOverwrite   bool // does not overwrite a client-supplied header when authenticated
	kerberosBroke bool // negotiation always fails
}

func (f fakeNginx) do(r checkRequest) (checkResponse, error) {
	u, _ := url.Parse(r.url)
	req := httptest.NewRequest(r.method, u.Path, strings.NewReader(r.body))
	for _, h := range r.headers {
		name, value, _ := strings.Cut(h, ": ")
		req.Header.Add(name, value)
	}
	client := req.Header.Get(identityHeader)
	req.Header.Del(identityHeader)
	public := u.Path == "/issuer" || strings.HasSuffix(u.Path, "/jwks.json") || strings.HasSuffix(u.Path, "/openid-configuration")
	switch {
	case public:
	case f.noAuth:
		req.Header.Set(identityHeader, client)
	case !r.negotiate || f.kerberosBroke:
		if f.trustClient && client != "" {
			req.Header.Set(identityHeader, client)
		} else {
			return checkResponse{status: 401}, nil
		}
	default:
		if f.noOverwrite && client != "" {
			req.Header.Set(identityHeader, client)
		} else {
			req.Header.Set(identityHeader, f.principal)
		}
	}
	w := httptest.NewRecorder()
	f.i.handler().ServeHTTP(w, req)
	return checkResponse{status: w.Code, body: w.Body.Bytes(), location: w.Header().Get("Location")}, nil
}

func runAgainst(t *testing.T, f fakeNginx, extra ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	args := append([]string{"-url", f.i.config.Issuer, "-audience", "test-api"}, extra...)
	code := runCheck(args, &out, f)
	return code, out.String()
}

func TestCheckHealthyDeploymentPasses(t *testing.T) {
	code, out := runAgainst(t, fakeNginx{i: fixture(t), principal: "alice@EXAMPLE"}, "-principal", "alice@EXAMPLE")
	if code != 0 || strings.Contains(out, "FAIL") || strings.Contains(out, "WARN") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{"token verifies", "nginx overwrites identity header", "Kerberos required", "0 failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "eyJ") {
		t.Fatal("report leaked a token")
	}
}

func TestCheckDetectsMisconfigurations(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*fakeNginx)
		want  string // text expected in the FAIL output
	}{
		{"nginx not requiring Kerberos", func(f *fakeNginx) { f.noAuth = true }, "forged identity header ignored"},
		{"nginx trusts client identity header", func(f *fakeNginx) { f.trustClient = true }, "forged identity header ignored"},
		{"nginx fails to overwrite header", func(f *fakeNginx) { f.noOverwrite = true }, "nginx overwrites identity header"},
		{"Kerberos login broken", func(f *fakeNginx) { f.kerberosBroke = true }, "Kerberos login"},
		{"principal not in config", func(f *fakeNginx) { f.principal = "mallory@EXAMPLE" }, "principal authorized"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := fakeNginx{i: fixture(t), principal: "alice@EXAMPLE"}
			c.setup(&f)
			code, out := runAgainst(t, f)
			if code != 1 || !strings.Contains(out, "FAIL  "+c.want) {
				t.Fatalf("exit %d, want a FAIL for %q\n%s", code, c.want, out)
			}
			if !strings.Contains(out, "fix:") {
				t.Error("failure lacks a hint")
			}
		})
	}
}

func TestCheckDetectsIssuerMismatchAndBadAudience(t *testing.T) {
	f := fakeNginx{i: fixture(t), principal: "alice@EXAMPLE"}
	var out bytes.Buffer
	// Public URL differs from the configured issuer (e.g. trailing path wrong).
	code := runCheck([]string{"-url", "https://auth.example/issuer", "-audience", "unconfigured"}, &out, f)
	if code != 1 || !strings.Contains(out.String(), "audience configured") {
		t.Fatalf("%d\n%s", code, out.String())
	}
	f.i.config.Issuer = "https://auth.example/other"
	f.i.discoveryJSON = []byte(`{"issuer":"https://auth.example/other","jwks_uri":"https://auth.example/other/jwks.json","id_token_signing_alg_values_supported":["RS256"]}`)
	out.Reset()
	code = runCheck([]string{"-url", "https://auth.example/issuer", "-audience", "test-api", "-public-only"}, &out, f)
	if code != 1 || !strings.Contains(out.String(), "discovery content") {
		t.Fatalf("%d\n%s", code, out.String())
	}
}

func TestCheckPublicOnlyNeedsNoKerberos(t *testing.T) {
	f := fakeNginx{i: fixture(t), kerberosBroke: true}
	var out bytes.Buffer
	if code := runCheck([]string{"-url", f.i.config.Issuer, "-public-only"}, &out, f); code != 0 || !strings.Contains(out.String(), "SKIP") {
		t.Fatalf("%d\n%s", code, out.String())
	}
}

func TestCheckUsageErrors(t *testing.T) {
	var out bytes.Buffer
	if runCheck(nil, &out, nil) != 2 || runCheck([]string{"-url", "https://x/issuer"}, &out, nil) != 2 || runCheck([]string{"-bogus"}, &out, nil) != 2 {
		t.Fatal("missing arguments must exit 2")
	}
}

// The consumer-side verification must reject everything a hostile token could try.
func TestCheckVerifyTokenRejects(t *testing.T) {
	i := fixture(t)
	k := &checker{base: i.config.Issuer, audience: "test-api", now: time.Now}
	raw := mintToken(t, i, "alice@EXAMPLE", "test-api")
	if _, err := k.verifyToken(raw, i.jwks); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	parts := strings.Split(raw, ".")
	tampered := parts[0] + "." + parts[1][:len(parts[1])-2] + "AA." + parts[2]
	other := fixture(t)
	for name, c := range map[string]struct {
		raw  string
		keys []publicJWK
		k    *checker
	}{
		"tampered payload": {tampered, i.jwks, k},
		"unknown kid":      {raw, other.jwks, k},
		"wrong audience":   {raw, i.jwks, &checker{base: k.base, audience: "other", now: time.Now}},
		"wrong issuer":     {raw, i.jwks, &checker{base: "https://evil.example/issuer", audience: "test-api", now: time.Now}},
		"expired":          {raw, i.jwks, &checker{base: k.base, audience: "test-api", now: func() time.Time { return time.Now().Add(time.Hour) }}},
		"not yet valid":    {raw, i.jwks, &checker{base: k.base, audience: "test-api", now: func() time.Time { return time.Now().Add(-time.Hour) }}},
		"not a JWS":        {"abc", i.jwks, k},
	} {
		if _, err := c.k.verifyToken(c.raw, c.keys); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

type unreachable struct{}

func (unreachable) do(checkRequest) (checkResponse, error) {
	return checkResponse{}, errors.New("curl: (7) Failed to connect")
}

func TestCheckUnreachableReportsOnceAndFails(t *testing.T) {
	var out bytes.Buffer
	if code := runCheck([]string{"-url", "https://auth.example/issuer", "-audience", "x"}, &out, unreachable{}); code != 1 {
		t.Fatal(code)
	}
	if strings.Count(out.String(), "FAIL") != 1 || strings.Contains(out.String(), "curl: curl:") {
		t.Fatalf("noisy output:\n%s", out.String())
	}
}
