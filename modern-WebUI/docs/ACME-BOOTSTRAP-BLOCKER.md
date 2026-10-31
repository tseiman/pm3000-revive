# ACME first-run bootstrap blocker — resolved

The first-run bootstrap blocker is resolved in the current source and in the
physically accepted production `pm3000-acme` binary. Its SHA-256 is:

`0aa205b837fa357cf3d7d0eb8a67c3df10fd929d9a8dc5c3a41c0383416832c0`

Physical acceptance proved the exact production binary's initial
`status` contract (`{"state":"never_run"}`, exit 0). A path-only diagnostic
variant separately proved first-run managed PEM creation, configuration
creation and read-back/revision, repeated-create exit 5, safe modes, absence of
renewal state, and complete `/tmp` cleanup. The diagnostic result does not
replace the production-binary hash gate.

The WebUI administration path now has closed first-run behavior:

- `GET /api/v1/settings/acme` projects `configured: false`, managed-CA
  presence, and `never_run` without inventing configuration values.
- First CA upload and configuration creation require `If-None-Match: *`, a
  valid browser session and CSRF authorization, and fixed-purpose broker
  operations that refuse to overwrite existing state.
- Existing configuration changes retain strong revision preconditions.
- Installation still creates directories only. It does not create ACME
  configuration, perform renewal, or install a scheduler.

`build-accepted-release.sh` rebuilds every other current release component but
copies only the exact accepted ACME bytes into `bin/pm3000-acme` and checks the
hash before and after packaging. `post-install-read-only-acceptance.sh` checks
the installed binary status exit and an authenticated HTTPS projection of the
ACME page as either the exact first-run state or the closed configured schema.
Real CA/configuration writes and renewal remain separate, explicit operator
actions.