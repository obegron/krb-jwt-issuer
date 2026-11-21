package main

// "krb-jwt-issuer check": a self-test an operator runs against a live
// deployment to catch misconfiguration. It needs only this binary and a curl
// built with GSS-API (curl performs the Kerberos negotiation).
//
// It verifies from the outside what the README promises: public metadata works,
// nginx demands Kerberos, nginx overwrites a forged identity header, the issuer
// authorizes the principal, and a minted token verifies against the published
// keys. Bearer tokens are never printed.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os/exec"
	"slices"
	"strings"
	"time"
)

type checkRequest struct {
	method, url, body string
	headers           []string // "Name: value"
	negotiate         bool     // authenticate with Kerberos (curl --negotiate)
}

type checkResponse struct {
	status   int
	body     []byte
	location string
}

type checkClient interface {
	do(checkRequest) (checkResponse, error)
}

// curlClient performs requests with curl so Kerberos/SPNEGO, the system trust
// store and proxy rules behave exactly as they do for the operator's own tools.
type curlClient struct{ cacert string }

func (c curlClient) do(r checkRequest) (checkResponse, error) {
	args := []string{"-sS", "--noproxy", "*", "--max-time", "15", "-X", r.method, "-w", "\n%{http_code} %{redirect_url}"}
	if c.cacert != "" {
		args = append(args, "--cacert", c.cacert)
	}
	if r.negotiate {
		args = append(args, "--negotiate", "-u", ":")
	}
	for _, h := range r.headers {
		args = append(args, "-H", h)
	}
	if r.body != "" {
		args = append(args, "--data-binary", r.body)
	}
	out, err := exec.Command("curl", append(args, r.url)...).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return checkResponse{}, fmt.Errorf("curl: %s", strings.TrimSpace(string(exit.Stderr)))
		}
		return checkResponse{}, fmt.Errorf("cannot run curl: %w", err)
	}
	cut := strings.LastIndexByte(string(out), '\n')
	if cut < 0 {
		return checkResponse{}, errors.New("unexpected curl output")
	}
	var resp checkResponse
	resp.body = out[:cut]
	fields := strings.Fields(string(out[cut+1:]))
	if len(fields) == 0 {
		return checkResponse{}, errors.New("unexpected curl output")
	}
	if _, err := fmt.Sscanf(fields[0], "%d", &resp.status); err != nil {
		return checkResponse{}, err
	}
	if len(fields) > 1 {
		resp.location = fields[1]
	}
	return resp, nil
}

type checker struct {
	client                checkClient
	out                   io.Writer
	base, audience        string
	principal             string
	now                   func() time.Time
	pass, fail, warn, skp int
}

func (k *checker) report(level, name, detail, hint string) {
	fmt.Fprintf(k.out, " %-4s  %-34s %s\n", level, name, detail)
	if hint != "" {
		fmt.Fprintf(k.out, "       fix: %s\n", hint)
	}
	switch level {
	case "PASS":
		k.pass++
	case "FAIL":
		k.fail++
	case "WARN":
		k.warn++
	case "SKIP":
		k.skp++
	}
}

func (k *checker) get(path string, negotiate bool, headers ...string) (checkResponse, error) {
	return k.client.do(checkRequest{method: "GET", url: k.base + path, headers: headers, negotiate: negotiate})
}

func (k *checker) mint(body string, negotiate bool, headers ...string) (checkResponse, error) {
	headers = append([]string{"Content-Type: application/json", "X-Token-Request: 1"}, headers...)
	return k.client.do(checkRequest{method: "POST", url: k.base + "/mint", body: body, headers: headers, negotiate: negotiate})
}

func (k *checker) expect(name, path string, resp checkResponse, err error, want int, pass, hint string) bool {
	switch {
	case err != nil:
		k.report("FAIL", name, err.Error(), "check DNS, the TLS certificate (use -cacert for a private CA), and that nginx is reachable")
	case resp.status != want:
		k.report("FAIL", name, fmt.Sprintf("%s returned HTTP %d, expected %d", path, resp.status, want), hint)
	default:
		k.report("PASS", name, pass, "")
		return true
	}
	return false
}

func (k *checker) rsaKey(j publicJWK) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil || len(e) == 0 || len(e) > 4 {
		return nil, errors.New("bad exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
}

// verifyToken checks a compact RS256 JWS against published keys and the
// expected issuer and audience, the way a well-behaved consumer would.
func (k *checker) verifyToken(raw string, keys []publicJWK) (tokenClaims, error) {
	var claims tokenClaims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return claims, errors.New("not a compact JWS")
	}
	var header struct{ Alg, Kid, Typ string }
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil {
		return claims, errors.New("unreadable header")
	}
	if header.Alg != "RS256" {
		return claims, fmt.Errorf("alg %q, expected RS256", header.Alg)
	}
	idx := slices.IndexFunc(keys, func(j publicJWK) bool { return j.Kid == header.Kid })
	if idx < 0 {
		return claims, fmt.Errorf("signing key %q is not published in the JWKS", header.Kid)
	}
	pub, err := k.rsaKey(keys[idx])
	if err != nil {
		return claims, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return claims, errors.New("unreadable signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
		return claims, errors.New("signature does not verify against the published key")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(pb, &claims) != nil {
		return claims, errors.New("unreadable claims")
	}
	now := k.now().Unix()
	switch {
	case claims.Issuer != k.base:
		return claims, fmt.Errorf("iss %q does not equal the issuer URL", claims.Issuer)
	case !slices.Contains(claims.Audience, k.audience):
		return claims, fmt.Errorf("aud %v does not contain %q", claims.Audience, k.audience)
	case claims.ExpiresAt <= now:
		return claims, errors.New("token is already expired (clock skew between this host and the Pi?)")
	case claims.NotBefore > now+60:
		return claims, errors.New("token is not yet valid (clock skew between this host and the Pi?)")
	case claims.ExpiresAt-claims.IssuedAt <= 0 || claims.ExpiresAt-claims.IssuedAt > 900:
		return claims, errors.New("lifetime outside 1..900 seconds")
	case claims.ID == "" || claims.Subject == "":
		return claims, errors.New("missing jti or sub")
	}
	return claims, nil
}

// publicChecks returns the published keys, and false if the server could not
// be reached at all (in which case every later check would only repeat that).
func (k *checker) publicChecks() ([]publicJWK, bool) {
	resp, err := k.get("/.well-known/openid-configuration", false)
	if err != nil {
		k.report("FAIL", "connect", strings.TrimPrefix(err.Error(), "curl: "), "check the hostname resolves to the Pi, port 443 is reachable, and the TLS certificate is trusted (-cacert for a private CA)")
		return nil, false
	}
	if k.expect("discovery document", "/.well-known/openid-configuration", resp, err, 200, "", "nginx must serve discovery without Kerberos (location with auth_gss off); see deploy/nginx.conf") {
		var d struct {
			Issuer  string   `json:"issuer"`
			JWKSURI string   `json:"jwks_uri"`
			Algs    []string `json:"id_token_signing_alg_values_supported"`
		}
		switch {
		case json.Unmarshal(resp.body, &d) != nil:
			k.report("FAIL", "discovery content", "response is not JSON", "the request may be reaching the wrong server block; check server_name")
		case d.Issuer != k.base:
			k.report("FAIL", "discovery content", fmt.Sprintf("issuer is %q, expected %q", d.Issuer, k.base), `"issuer" in config.json must equal the public URL exactly, including the /issuer path and no trailing slash`)
		case d.JWKSURI != k.base+"/jwks.json" || !slices.Contains(d.Algs, "RS256"):
			k.report("FAIL", "discovery content", "jwks_uri or signing algorithm is unexpected", "restart krb-jwt-issuer after fixing config.json")
		default:
			k.report("PASS", "discovery content", "issuer and jwks_uri match the URL", "")
		}
	}
	var keys []publicJWK
	resp, err = k.get("/jwks.json", false)
	if k.expect("public keys (JWKS)", "/jwks.json", resp, err, 200, "", "nginx must serve /issuer/jwks.json without Kerberos; see deploy/nginx.conf") {
		var doc struct {
			Keys []publicJWK `json:"keys"`
		}
		var raw struct {
			Keys []map[string]any `json:"keys"`
		}
		ok := json.Unmarshal(resp.body, &doc) == nil && json.Unmarshal(resp.body, &raw) == nil && len(doc.Keys) > 0
		leaked := ""
		for _, m := range raw.Keys {
			for _, f := range []string{"d", "p", "q", "dp", "dq", "qi"} {
				if _, found := m[f]; found {
					leaked = f
				}
			}
		}
		switch {
		case !ok:
			k.report("FAIL", "public key content", "no usable keys in the response", "check the issuer logs: journalctl -u krb-jwt-issuer")
		case leaked != "":
			k.report("FAIL", "public key content", "PRIVATE key member \""+leaked+"\" is published", "stop the service and report this; do not use this deployment")
		default:
			bad := ""
			for _, j := range doc.Keys {
				pub, err := k.rsaKey(j)
				if err != nil || jwkFor(pub).Kid != j.Kid {
					bad = j.Kid
				}
			}
			if bad != "" {
				k.report("FAIL", "public key content", "kid "+bad+" is not the key's RFC 7638 thumbprint", "")
			} else {
				keys = doc.Keys
				k.report("PASS", "public key content", fmt.Sprintf("%d public key(s), no private material", len(keys)), "")
			}
		}
	}
	resp, err = k.get("", false)
	switch {
	case err != nil || resp.status != 302 || resp.location != k.base+"/.well-known/openid-configuration":
		k.report("WARN", "issuer root redirect", "GET "+k.base+" does not redirect to discovery", "optional; add the `location = /issuer` block from deploy/nginx.conf")
	default:
		k.report("PASS", "issuer root redirect", "redirects to the discovery document", "")
	}
	return keys, true
}

func (k *checker) protectedChecks(keys []publicJWK) {
	spoof := "X-Authenticated-Principal: mallory@EXAMPLE.INVALID"
	resp, err := k.get("/whoami", false)
	k.expect("Kerberos required", "/whoami", resp, err, 401, "anonymous request is rejected",
		"nginx must run auth_gss on for this location; 403 means the request bypassed nginx authentication (check proxy_pass and location blocks)")
	resp, err = k.get("/whoami", false, spoof)
	k.expect("forged identity header ignored", "/whoami", resp, err, 401, "a client-supplied X-Authenticated-Principal gains nothing",
		"nginx must require Kerberos (auth_gss on) and set X-Authenticated-Principal from $remote_user, never pass the client's value through")
	resp, err = k.mint(`{"audience":"`+k.audience+`"}`, false)
	k.expect("anonymous mint refused", "/mint", resp, err, 401, "no token without Kerberos", "nginx must require Kerberos for /issuer/mint")

	resp, err = k.get("/whoami", true)
	if err != nil || resp.status == 401 {
		detail := "HTTP 401 with Kerberos"
		if err != nil {
			detail = err.Error()
		}
		k.report("FAIL", "Kerberos login", detail, "run `klist` (need a valid TGT; `kinit user@REALM`); the HTTP/<host> service principal and keytab must exist; for browsers see DisableAuthNegotiateCnameLookup; curl needs GSS-API support (`curl -V`)")
		k.report("SKIP", "remaining authenticated checks", "need a working Kerberos login", "")
		return
	}
	var who struct {
		Subject   string   `json:"subject"`
		Audiences []string `json:"audiences"`
		Issuer    string   `json:"issuer"`
	}
	switch {
	case resp.status == 403:
		k.report("FAIL", "principal authorized", "Kerberos works but the issuer refused this principal", "add your exact principal (case-sensitive) to \"subjects\" in /etc/krb-jwt-issuer/config.json and restart the service")
		k.report("SKIP", "remaining authenticated checks", "principal not authorized", "")
		return
	case resp.status != 200 || json.Unmarshal(resp.body, &who) != nil:
		k.report("FAIL", "identity endpoint", fmt.Sprintf("HTTP %d", resp.status), "check journalctl -u krb-jwt-issuer and nginx error.log; 502 means the socket permissions are wrong (www-data must own /run/krb-jwt-issuer.sock)")
		return
	}
	switch {
	case k.principal != "" && who.Subject != k.principal:
		k.report("FAIL", "principal matches", fmt.Sprintf("authenticated as %q, expected %q", who.Subject, k.principal), "")
	default:
		k.report("PASS", "principal authorized", "authenticated as "+who.Subject, "")
	}
	if !slices.Contains(who.Audiences, k.audience) {
		k.report("FAIL", "audience configured", fmt.Sprintf("%q is not an audience for this principal (allowed: %v)", k.audience, who.Audiences), "add the audience to this principal's list in config.json and restart")
		return
	}
	k.report("PASS", "audience configured", k.audience, "")

	real := who.Subject
	resp, err = k.get("/whoami", true, spoof)
	if err == nil && resp.status == 200 && json.Unmarshal(resp.body, &who) == nil && who.Subject == real {
		k.report("PASS", "nginx overwrites identity header", "forged header replaced by the Kerberos principal", "")
	} else {
		k.report("FAIL", "nginx overwrites identity header", "a client-supplied identity was honoured or the request failed", "use `proxy_set_header X-Authenticated-Principal $remote_user;` in every authenticated location")
	}

	resp, err = k.mint(`{"audience":"`+k.audience+`"}`, true)
	var minted struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	switch {
	case err != nil || resp.status == 429:
		k.report("FAIL", "mint a token", "rate limited or request failed", "wait a minute and retry")
	case resp.status != 200 || json.Unmarshal(resp.body, &minted) != nil || minted.AccessToken == "":
		k.report("FAIL", "mint a token", fmt.Sprintf("HTTP %d", resp.status), "see the issuer logs; 400/415 means nginx is altering the request body or headers")
	case keys == nil:
		k.report("SKIP", "token verifies", "no public keys were available", "")
	default:
		claims, err := k.verifyToken(minted.AccessToken, keys)
		if err != nil {
			k.report("FAIL", "token verifies", err.Error(), "")
		} else {
			k.report("PASS", "token verifies", fmt.Sprintf("signature, iss, aud, exp ok (sub %s, %ds lifetime)", claims.Subject, claims.ExpiresAt-claims.IssuedAt), "")
		}
	}

	resp, err = k.mint(`{"audience":"not-a-configured-audience"}`, true)
	k.expect("unconfigured audience refused", "/mint", resp, err, 403, "refused", "the issuer must only mint for audiences listed in config.json")
	resp, err = k.mint(`{"audience":"`+k.audience+`"}`, true, "Origin: https://evil.example")
	k.expect("foreign origin refused", "/mint", resp, err, 403, "cross-origin mint blocked", "the issuer rejects Origin headers that differ from the issuer origin; do not strip them in nginx")
	resp, err = k.client.do(checkRequest{method: "POST", url: k.base + "/mint", body: `{"audience":"` + k.audience + `"}`, headers: []string{"Content-Type: application/json"}, negotiate: true})
	k.expect("CSRF header required", "/mint", resp, err, 400, "request without X-Token-Request refused", "")
}

// runCheck returns a process exit code: 0 healthy, 1 a check failed, 2 usage.
func runCheck(args []string, out io.Writer, client checkClient) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(out)
	url := fs.String("url", "", "issuer URL, e.g. https://auth.example.com/issuer (required)")
	audience := fs.String("audience", "", "audience to request (required)")
	principal := fs.String("principal", "", "expected Kerberos principal (optional)")
	cacert := fs.String("cacert", "", "CA bundle for a private certificate authority")
	publicOnly := fs.Bool("public-only", false, "skip Kerberos checks (for hosts without a ticket, such as the machine that will verify tokens)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *url == "" || (*audience == "" && !*publicOnly) {
		fmt.Fprintln(out, "usage: krb-jwt-issuer check -url https://auth.example.com/issuer -audience NAME [-principal user@REALM] [-cacert ca.pem] [-public-only]")
		return 2
	}
	if client == nil {
		client = curlClient{cacert: *cacert}
	}
	k := &checker{client: client, out: out, base: strings.TrimRight(*url, "/"), audience: *audience, principal: *principal, now: time.Now}
	fmt.Fprintf(out, "krb-jwt-issuer %s check of %s\n", version, k.base)
	keys, reachable := k.publicChecks()
	if !reachable {
		fmt.Fprintf(out, "\n%d passed, %d failed, %d warnings, %d skipped\n", k.pass, k.fail, k.warn, k.skp)
		return 1
	}
	if *publicOnly {
		k.report("SKIP", "Kerberos and token checks", "-public-only", "")
	} else {
		k.protectedChecks(keys)
	}
	fmt.Fprintf(out, "\n%d passed, %d failed, %d warnings, %d skipped\n", k.pass, k.fail, k.warn, k.skp)
	if k.fail > 0 {
		return 1
	}
	if *publicOnly {
		fmt.Fprintln(out, "Only public endpoints were checked; Kerberos, authorization and token issuing were NOT tested.")
	}
	return 0
}
