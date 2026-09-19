# Security

This repository holds the Presift **client**: a composite GitHub Action and one launcher file. The
analysis engine is a separate signed release that the launcher downloads and runs on your machine.

## Reporting a vulnerability

Open a private GitHub Security Advisory on this repository. If that is unavailable to you, open an
issue that says only that you have a security report and asks for a contact route — do not put
details in a public issue. There is no bug bounty. This is a small product: expect a considered
answer rather than a fast one, and no guaranteed response time.

## What the client does

- Sends, to the release service only: your key, the client version, the platform, and the requested
  channel or pinned version. Nothing else — no SQL, file names, findings or repository content.
- Downloads the release over HTTPS using a short-lived URL, and verifies before executing:
  the manifest's shape, its **Ed25519 signature** against a public key compiled into the launcher,
  and the **SHA-256 of the received bytes** against the signed digest.
- Deletes anything that fails verification instead of running it, and exits `2`.
- Caches the verified release under `0700`, keyed by version and digest, and re-verifies a cached
  file before reusing it.
- Never writes your key to stdout, stderr or a file; messages containing it are redacted.

## What it does not do

- No database connection, and no upload of migration content.
- No telemetry, no usage reporting, no analytics in CI.
- No execution of anything that has not passed signature and digest verification.

## Permissions

The Action needs `contents: read`. Add `security-events: write` only if *you* upload the SARIF file
to code scanning.

## Handling your key

Store it as a repository or organisation secret and pass it through the `license` input. Because
GitHub withholds secrets from fork-triggered workflows, the check cannot run on fork pull requests;
do not work around this with `pull_request_target` and a fork checkout, which would expose your
secrets to unreviewed code.

## What is not claimed

The integrity chain above protects what runs on your runner. It is not a claim that the compiled
release cannot be reverse-engineered, that licensing cannot be circumvented, that builds are
bit-for-bit reproducible, or that any system is absolutely secure.
