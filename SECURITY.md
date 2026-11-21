# Security policy

This service mints bearer tokens that other systems trust, so please report
vulnerabilities privately rather than in a public issue.

Use GitHub's **Report a vulnerability** button on the repository's Security tab
(private vulnerability reporting). Include the version (`krb-jwt-issuer -version`),
your deployment shape (nginx, Kerberos module), and reproduction steps.

This is a personal project maintained on a best-effort basis, with no support
commitment or response-time guarantee. Fixes land in the latest release only.

Out of scope: weaknesses that require write access to the signing key, the
Unix socket (which is the trust boundary), `/etc/krb-jwt-issuer/config.json`, or
the nginx configuration.
