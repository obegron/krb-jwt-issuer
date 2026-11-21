# Releasing

One-time repository settings (GitHub → Settings):

1. **General → Releases → Enable release immutability.** Published releases then
   cannot have assets changed or be deleted, and their tag cannot be moved.
2. **Rules → Rulesets**: protect `main` (pull request, required status checks
   `test` and `vulncheck`, block force pushes) and protect tags `v*` (block
   deletion and updates). If you also restrict tag *creation*, add yourself as a
   bypass actor, or you will not be able to push release tags.
3. **Code security**: enable private vulnerability reporting, secret scanning
   with push protection, and Dependabot alerts.
4. **Actions → General**: default workflow permissions "Read repository contents".

Cutting a release:

1. Merge to `main` with CI green. Tag a commit that CI has run on (normally the
   tip of `main`): the workflow refuses a commit without a successful CI run. Update upgrade notes in the README if needed.
2. Rehearse with a pre-release tag: `git tag -s v0.1.0-rc1 && git push origin v0.1.0-rc1`.
   Immutable tags can never be reused, so never skip the rehearsal for a new pipeline.
3. Tag the real release the same way. The workflow tests, builds three
   architectures, writes `SHA256SUMS`, attests build provenance, creates a draft
   release, uploads everything, and publishes it.

If the workflow fails before the publish step, nothing is locked: the tag is not
immutable until the release is published. Fix the cause and re-run the failed
workflow; it deletes a leftover *draft* release before recreating it and never
touches a published one. If a *published* release is wrong, it cannot be edited:
ship a new version instead.

Verify a download (this is what consumers should do before `install.py`):

`gh release verify` needs a recent GitHub CLI (immutable-release support is new;
upgrade `gh` if the command is missing).

```bash
gh release verify v0.1.0 -R obegron/krb-jwt-issuer
gh attestation verify krb-jwt-issuer-v0.1.0-linux-armv7.tar.gz -R obegron/krb-jwt-issuer
sha256sum -c --ignore-missing SHA256SUMS
```

Compare the executable's digest with `SHA256SUMS` on the machine you install on,
or pass it to the installer (`--sha256`) so a swapped file is refused.

The executable embeds its build metadata: `go version -m ./krb-jwt-issuer`
lists the Go toolchain and (empty) dependency set, serving as an SBOM.
