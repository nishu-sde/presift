# Failure modes and error codes

Presift is fail-closed. If the client cannot prove that it is about to run an authentic,
entitled release, it refuses and exits `2` rather than analysing anything.

Every refusal prints `presift: <message>` on stderr and, in GitHub Actions, an `::error` annotation
tagged with the stable code below. Codes do not change between releases; wording may.

| Code | Meaning | What to do |
|---|---|---|
| `no-key` | no key in `PRESIFT_LICENSE` and not running in GitHub Actions | outside Actions an organisation key is required; the evaluation exists only in Actions — see https://presift.dev/trial |
| `no-oidc` | in GitHub Actions without a key, but the job cannot request an OIDC token | add `permissions: id-token: write` to the job (the evaluation starts automatically), or pass an organisation key as the `license` input |
| `bad-oidc` | GitHub's job token was not accepted by the Presift service | re-run once; if it persists, report it — the token is issued by GitHub for exactly this service |
| `oidc-expired` | GitHub's job token expired before it reached the service | re-run the job |
| `trial-expired` | your organisation's 30-day evaluation has ended | buy an organisation licence at https://presift.dev/pricing and pass it as `license` |
| `paid-expired` | the organisation licence has expired and its grace period is over | renew at https://presift.dev/pricing or retrieve the current key at https://presift.dev/key |
| `no-key-fork` | same, in a context where GitHub withholds repository secrets (fork pull request, restricted actor) | run the check on the base repository, in a merge queue, or after merge — not via `pull_request_target` |
| `bad-key` | the supplied key is malformed or not signed by Presift | check the secret; retrieve your organisation key at https://presift.dev/key |
| `unsupported-platform` | no release is published for this runner's OS/architecture | use a Linux x86_64 runner |
| `artifact-unavailable` | no release matches the requested channel or pinned version | remove `core-version`, or pin a version that exists |
| `client-too-old` | the release requires a newer client | update the `uses:` reference |
| `signature-failed` | the release manifest is not signed by a trusted Presift key | do not retry blindly; report it |
| `digest-failed` | the downloaded bytes do not match the signed digest | usually a truncated or tampered download; the file is deleted, retry once, then report it |
| `download-failed` | network failure while downloading | retry; check egress from the runner |
| `service-unavailable` | the release service could not be reached | the run falls back to a verified cached release when one exists, otherwise retry later |
| `manifest-invalid` | the service returned a manifest that does not meet the expected shape | report it |

The evaluation token obtained in GitHub Actions is used in memory for the job only: it is never written to disk, cached or printed.

`signature-failed`, `digest-failed` and `manifest-invalid` mean verification failed. Nothing is
executed in those cases and the cached slot is removed.

## Analysis exit codes

| Code | Meaning |
|---|---|
| `0` | no finding at or above `fail-on` |
| `1` | findings at or above `fail-on` |
| `2` | refused to run (any code above) |

A `2` is never a finding count. Treat it as a broken step, not as a failing check.
