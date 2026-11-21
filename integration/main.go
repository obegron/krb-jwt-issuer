// End-to-end verification with the same discovery/JWKS client family used by
// Kubernetes. Tokens stay in memory and are never printed.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Deployment under test, supplied by the environment so no site-specific
// values live in the repository:
//
//	ISSUER_URL   e.g. https://auth.example.com/issuer           (required)
//	PRINCIPAL    your Kerberos principal, e.g. alice@EXAMPLE.COM (required)
//	AUDIENCE     an audience configured for PRINCIPAL            (default homelab-test)
//	RESTART_CMD  optional shell command that restarts the issuer service,
//	             e.g. "ssh admin@issuer-host sudo -n systemctl restart krb-jwt-issuer.service"
var (
	issuer    = strings.TrimRight(os.Getenv("ISSUER_URL"), "/")
	principal = os.Getenv("PRINCIPAL")
	audience  = envOr("AUDIENCE", "homelab-test")
	restart   = os.Getenv("RESTART_CMD")
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func must(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func curl(auth bool, path, body string, extra ...string) []byte {
	args := []string{"--noproxy", "*", "--max-time", "15", "--fail", "-sS"}
	if auth {
		args = append(args, "--negotiate", "-u", ":")
	}
	if body != "" {
		args = append(args, "-H", "Content-Type: application/json", "-H", "X-Token-Request: 1", "--data-binary", body)
	}
	args = append(args, extra...)
	args = append(args, issuer+path)
	b, err := exec.Command("curl", args...).Output()
	if err != nil {
		panic(fmt.Sprintf("request to %s failed: %v", path, err))
	}
	return b
}

func status(auth bool, body string, extra ...string) string {
	args := []string{"--noproxy", "*", "--max-time", "15", "-sS", "-o", "/dev/null", "-w", "%{http_code}"}
	if auth {
		args = append(args, "--negotiate", "-u", ":")
	}
	args = append(args, "-H", "Content-Type: application/json", "-H", "X-Token-Request: 1", "--data-binary", body)
	args = append(args, extra...)
	args = append(args, issuer+"/mint")
	b, err := exec.Command("curl", args...).Output()
	if err != nil {
		panic(err)
	}
	return string(b)
}

var audienceBody = `{"audience":"` + audience + `"}`

func main() {
	if issuer == "" || principal == "" {
		fmt.Fprintln(os.Stderr, "set ISSUER_URL and PRINCIPAL (see the comment at the top of main.go)")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		panic(err)
	}
	fmt.Println("Public issuer discovery: passed")
	var who struct {
		Subject string `json:"subject"`
	}
	if err := json.Unmarshal(curl(true, "/whoami", "", "-H", "X-Authenticated-Principal: mallory@"+strings.SplitN(principal, "@", 2)[1]), &who); err != nil {
		panic(err)
	}
	must(who.Subject == principal, "nginx did not overwrite the supplied identity header")
	fmt.Println("Kerberos identity and proxy header overwrite: passed")
	must(status(false, audienceBody) == "401", "anonymous mint was not denied")
	must(status(false, audienceBody, "-H", "X-Authenticated-Principal: "+principal) == "401", "spoofed anonymous identity was accepted")
	must(status(true, `{"audience":"admin-api"}`) == "403", "unconfigured audience was accepted")
	must(status(true, `{"audience":"`+audience+`","sub":"root"}`) == "400", "claims injection was accepted")
	must(status(true, audienceBody, "-H", "Origin: https://evil.example") == "403", "foreign-origin mint was accepted")
	fmt.Println("Anonymous, spoofed identity, audience, claims, and origin rejection: passed")
	var minted struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(curl(true, "/mint", audienceBody), &minted); err != nil {
		panic(err)
	}
	must(minted.ExpiresIn == 600, "unexpected lifetime")
	verifier := provider.Verifier(&oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256"}})
	verified, err := verifier.Verify(ctx, minted.AccessToken)
	if err != nil {
		panic(err)
	}
	must(verified.Subject == principal, "wrong token subject")
	_, err = provider.Verifier(&oidc.Config{ClientID: "another-app", SupportedSigningAlgs: []string{"RS256"}}).Verify(ctx, minted.AccessToken)
	must(err != nil, "wrong audience verified")
	fmt.Println("Independent discovery/JWKS signature, issuer, audience, and expiry verification: passed")
	// A restart must keep the signing identity stable and old tokens valid.
	if restart == "" {
		fmt.Println("Restart persistence check: skipped (RESTART_CMD not set)")
	} else {
		before := string(curl(false, "/jwks.json", ""))
		if out, err := exec.Command("sh", "-c", restart).CombinedOutput(); err != nil {
			panic(fmt.Sprintf("restart failed: %v %s", err, out))
		}
		must(before == string(curl(false, "/jwks.json", "")), "public key changed on restart")
		if _, err := verifier.Verify(ctx, minted.AccessToken); err != nil {
			panic(err)
		}
		fmt.Println("Signing key persists across service restart: passed")
	}
	// The bare issuer URL redirects to discovery without Kerberos.
	noFollow := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	root, err := noFollow.Get(issuer)
	if err != nil {
		panic(err)
	}
	root.Body.Close()
	must(root.StatusCode == 302 && root.Header.Get("Location") == issuer+"/.well-known/openid-configuration", "issuer root does not redirect to discovery")
	fmt.Println("Issuer root redirects to discovery: passed")
	// Check that the published keys have no private RSA parameters.
	response, err := client.Get(issuer + "/jwks.json")
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	public, _ := io.ReadAll(response.Body)
	for _, field := range []string{`"d":`, `"p":`, `"q":`, "PRIVATE KEY"} {
		must(!strings.Contains(string(public), field), "private material in JWKS")
	}
	fmt.Println("Public JWKS contains only public key material: passed")
	fmt.Println("All deployed issuer checks passed; no bearer tokens printed.")
}
