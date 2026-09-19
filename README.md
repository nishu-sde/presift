# Presift — MySQL migration safety for CI

**Presift, by Nishu.** [presift.dev](https://presift.dev)

Presift reads your MySQL migration files and flags the statements that cause outages: **destructive
changes** that cannot be rolled back, and **`ALTER TABLE` operations that copy or rebuild the table
or block concurrent writes**. It reports them on the pull request with the rule, the reasoning and
the MySQL manual reference, so the review happens before the migration reaches production.

This repository is the **client**: a composite GitHub Action and one launcher file. It contains no
analysis logic. The launcher authenticates with your key, downloads the signed Presift release,
verifies it, caches it and runs it **on your own runner**.

## Your migrations stay on your machine

The analysis is a local process on your runner. Presift makes no database connection and reads no
schema. The only request the client makes is to the release service, and it sends exactly four
things: your key, the client version, the platform, and the requested channel or pinned version.
It never sends SQL, file names, findings, repository content or results. There is no telemetry and
no usage reporting.

## Use it

```yaml
name: migration-safety
on: [pull_request]
permissions:
  contents: read
jobs:
  presift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: nishu-sde/presift@v1
        with:
          paths: db/migrations
          fail-on: error
          license: ${{ secrets.PRESIFT_LICENSE }}
```

More examples, including SARIF upload to code scanning, are in [`examples/`](examples).

## Getting a key

Presift is a paid tool. A **30-day evaluation key** gives you the complete product — no reduced
rule set, no watermark, no card: request one at [presift.dev/trial](https://presift.dev/trial).
After that it is an annual subscription per organisation; see
[presift.dev/pricing](https://presift.dev/pricing).

Store the key as a repository or organisation secret and pass it as the `license` input. The key is
bound to a GitHub organisation: in Actions it must match the repository owner.

## How the launcher obtains the core

1. The launcher POSTs your key, the client version, the platform and the channel to the release
   service.
2. The service answers with a release **manifest**, its **Ed25519 signature**, and a short-lived
   download URL.
3. The launcher checks the manifest's shape, verifies the signature against a public key compiled
   into this file, downloads the release and verifies the **SHA-256 of the bytes it received**
   against the signed digest.
4. Only if all of that passes does it store the release in a private cache (`0700`, keyed by
   version and digest) and execute it. A file that fails any check is deleted, not run.
5. If the service is unreachable, the launcher may reuse a cached release — but only after
   re-verifying its signature and digest. It never runs an unverified file.

Verification is offline: the signing public key is in the client, so a compromised or impersonated
service cannot make the launcher run something that was not signed for that release.

What this does and does not give you: it protects the integrity of what runs on your runner. It is
not a claim that the compiled release cannot be reverse-engineered, that the licensing cannot be
circumvented, or that the build is bit-for-bit reproducible. None of those are claimed.

## Requirements

- **Linux x86_64** runners — GitHub-hosted `ubuntu-*` and equivalent self-hosted runners. Other
  platforms are not supported yet; the launcher refuses rather than guessing.
- **Python 3.9+** on the runner (present on GitHub-hosted runners). The launcher uses only the
  standard library; nothing is installed.
- Outbound HTTPS from the runner to the release service, once per new release version (afterwards
  the cache is used).

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `paths` | `.` | files or directories containing `.sql` migrations |
| `fail-on` | `error` | minimum severity that fails the step: `error`, `warning`, `note`, `never` |
| `sarif-file` | – | also write a SARIF 2.1.0 report to this path |
| `rules` | all | comma-separated rule ids to enable |
| `license` | **required** | evaluation or organisation key |
| `channel` | `stable` | release channel |
| `core-version` | newest | pin an exact Presift version |

Per-project settings — enabling and disabling rules, severity overrides, ignored paths — live in a
`presift.toml` next to your migrations. See [`examples/presift.toml`](examples/presift.toml).

## What it reports

See [`docs/rules.md`](docs/rules.md) for the rules, their severities and how to suppress a finding
you have decided is intentional.

## Exit codes and failure modes

| Exit code | Meaning |
|---|---|
| `0` | no finding at or above `fail-on` |
| `1` | findings at or above `fail-on` |
| `2` | Presift refused to run (no valid key, unsupported platform, verification failure, service error) |

Every refusal prints a stable error code and a message that says what to do. The full list is in
[`docs/errors.md`](docs/errors.md).

## Fork pull requests

GitHub does not pass repository secrets to workflows triggered from a fork, so the key is not
available there and the step fails with an explicit message. Run the check on the base repository,
in a merge queue, or after merge. **Do not** use `pull_request_target` to check out and run code
from a fork with your secrets in scope.

## Support and security

Open an issue here for bugs in the client and for usage questions. For anything sensitive, see
[SECURITY.md](SECURITY.md).

## Licensing

This client — the Action, the launcher and these docs — is licensed under the
[Apache License 2.0](LICENSE). The **Presift core** that the launcher downloads is proprietary,
separately controlled, and not contained in this repository; the Apache licence grants no rights to
it. Using the core is subject to the Presift evaluation or commercial terms that apply to your key.
See [LICENSE.md](LICENSE.md).
