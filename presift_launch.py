#!/usr/bin/env python3
"""Presift launcher — fetches, verifies and runs the Presift release on this machine.

Presift, by Nishu.  https://presift.dev
Copyright 2026 Nishu. Licensed under the Apache License, Version 2.0; see the LICENSE file.

This file is the whole public client. It contains no analysis logic: it authenticates with your
entitlement key, downloads the signed release, verifies its signature and digest, caches it and
executes it locally. Your migration files never leave this machine.

Standard library only (no pip install), Python 3.9+.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform as _platform
import shutil
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

CLIENT_VERSION = "1.2.0"
SERVICE_URL = os.environ.get("PRESIFT_SERVICE_URL", "https://api.presift.dev")
TRIAL_URL = "https://presift.dev/trial"
PRICING_URL = "https://presift.dev/pricing"
KEY_URL = "https://presift.dev/key"
KEY_ENV = "PRESIFT_LICENSE"
# Actions-attested trial: in GitHub Actions, with `permissions: id-token: write`, the launcher asks GitHub for the job's
# OIDC token for exactly this audience and exchanges it at the service for a short-lived trial key bound to the
# repository owner. The OIDC token is used once, in memory, and is never printed, stored or passed to the core.
OIDC_AUDIENCE = "https://api.presift.dev"
OIDC_URL_ENV, OIDC_TOKEN_ENV = "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
SUPPORTED_PLATFORMS = ("linux-x86_64",)
NETWORK_TIMEOUT = 30
MAX_ARTIFACT_BYTES = 200 * 1024 * 1024

# Release verification keys: the public halves of the release signing identities. Fixed in this file
# on purpose — there is no environment override for the stable path, so a runner's environment cannot
# change which identities are trusted. Rotation ships a new client version with a new key id.
TRUSTED_KEYS: dict[str, str] = {
    "presift-release-1": "mG-w8vID8qixmyCipO7tF9Acxif1y52A_58kphZASgM",   # sha256 of the raw key: 495b42d811e33d11d8a5f11dce444d5d…
}

EXIT_OK, EXIT_FINDINGS, EXIT_REFUSED = 0, 1, 2


# --- messages (stable codes; never include the key, a URL signature or internal detail) ----------
def _fork_context() -> bool:
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    actor = os.environ.get("GITHUB_ACTOR", "")
    head, base = os.environ.get("GITHUB_HEAD_REF", ""), os.environ.get("GITHUB_REPOSITORY", "")
    return (event in ("pull_request", "pull_request_target") and bool(head) and
            os.environ.get("GITHUB_REPOSITORY_OWNER", "") not in base.split("/")[:1]) or actor.startswith("dependabot")


MESSAGES = {
    "no-key": f"Presift needs an organisation key in {KEY_ENV}, or — in GitHub Actions — `permissions: id-token: write` so the 30-day evaluation starts automatically. See {TRIAL_URL}.",
    "no-oidc": ("Presift can start your organisation's 30-day evaluation automatically, but this job may not request an OIDC token. "
                f"Add `permissions: id-token: write` to the job (or set the license input with an organisation key). See {TRIAL_URL}."),
    "bad-oidc": "GitHub's job token was not accepted by the Presift service — refusing to run.",
    "oidc-expired": "GitHub's job token had expired before it reached the Presift service; re-run the job.",
    "trial-expired": f"the 30-day evaluation for '{{org}}' ended on {{ended}}. Continued use needs an organisation licence: {PRICING_URL}",
    "paid-expired": f"the organisation licence has expired (grace period over). Renew at {PRICING_URL} or retrieve the current key at {KEY_URL}.",
    "no-key-fork": (f"Presift needs an evaluation or organisation key in {KEY_ENV}, but GitHub does not provide "
                    "repository secrets to workflows triggered from a fork or by a restricted actor. Run the check on "
                    "the base repository, in a merge queue, or after merge."),
    "bad-key": f"{KEY_ENV} is not a valid key. Get an evaluation key at {TRIAL_URL} or retrieve your organisation key at {KEY_URL}.",
    "unsupported-platform": "Presift does not provide a build for {platform} yet (supported: " + ", ".join(SUPPORTED_PLATFORMS) + ").",
    "artifact-unavailable": "no Presift release matches this request (channel {channel}, client {client}).",
    "signature-failed": "release verification failed — refusing to run.",
    "digest-failed": "downloaded file failed integrity verification — refusing to run.",
    "download-failed": "could not download the Presift release (network error).",
    "service-unavailable": f"the Presift release service is unavailable; try again later, or pin a cached version. Status: {KEY_URL}",
    "client-too-old": "this Presift release needs a newer action version (>= {min_client}); update the action reference.",
    "manifest-invalid": "release verification failed — refusing to run.",
}


class _Blank(dict):
    def __missing__(self, key: str) -> str:
        return "?"


def fail(code: str, **fmt: Any) -> int:
    text = MESSAGES.get(code, code).format_map(_Blank(fmt))
    sys.stderr.write(f"presift: {text}\n")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        sys.stdout.write(f"::error title=Presift ({code})::{text}\n")
    return EXIT_REFUSED


def redact(text: str, key: Optional[str]) -> str:
    return text.replace(key, "***") if key else text


# --- Ed25519 verification (RFC 8032), stdlib only ------------------------------------------------
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _point_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    a = ((p[1] - p[0]) * (q[1] - q[0])) % _P
    b = ((p[1] + p[0]) * (q[1] + q[0])) % _P
    c = (2 * p[3] * q[3] * _D) % _P
    d = (2 * p[2] * q[2]) % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(s: int, p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


_Gy = 4 * pow(5, _P - 2, _P) % _P
_G = (_recover_x(_Gy, 0), _Gy, 1, _recover_x(_Gy, 0) * _Gy % _P)


def _decompress(data: bytes) -> Optional[tuple[int, int, int, int]]:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _equal(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature. Returns False on any malformed input; never raises."""
    try:
        if len(signature) != 64 or len(public_key) != 32:
            return False
        a = _decompress(public_key)
        r = _decompress(signature[:32])
        if a is None or r is None:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
        return _equal(_point_mul(s, _G), _point_add(r, _point_mul(h, a)))
    except Exception:
        return False


def b64url_decode(text: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- manifest handling ---------------------------------------------------------------------------
def canonical(manifest: dict[str, Any]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def version_tuple(v: str) -> tuple[int, ...]:
    parts = []
    for chunk in str(v).split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts + [0, 0, 0])[:3]


def manifest_problems(m: dict[str, Any]) -> list[str]:
    problems = []
    if m.get("schema") != "presift.release/1":
        problems.append("schema")
    if m.get("product") != "presift":
        problems.append("product")
    for key in ("version", "platform", "filename", "artifact_sha256", "min_client", "key_id", "channel"):
        if not m.get(key):
            problems.append(key)
    digest = str(m.get("artifact_sha256", ""))
    if not digest.startswith("sha256:") or len(digest) != 71:
        problems.append("artifact_sha256")
    if not isinstance(m.get("size"), int) or m["size"] <= 0 or m["size"] > MAX_ARTIFACT_BYTES:
        problems.append("size")
    if "/" in str(m.get("filename", "")) or str(m.get("filename", "")).startswith("."):
        problems.append("filename")
    return problems


def current_platform() -> str:
    system = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}.get(_platform.system(), _platform.system().lower())
    machine = {"x86_64": "x86_64", "AMD64": "x86_64", "aarch64": "arm64", "arm64": "arm64"}.get(_platform.machine(), _platform.machine().lower())
    return f"{system}-{machine}"


# --- cache ---------------------------------------------------------------------------------------
def cache_root() -> Path:
    for var in ("PRESIFT_CACHE_DIR", "XDG_CACHE_HOME"):
        value = os.environ.get(var)
        if value:
            return Path(value) / ("presift" if var == "XDG_CACHE_HOME" else "")
    return Path.home() / ".cache" / "presift"


def cache_slot(manifest: dict[str, Any]) -> Path:
    digest = manifest["artifact_sha256"].split(":", 1)[1][:16]
    return cache_root() / "artifacts" / manifest["platform"] / manifest["version"] / digest


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return "sha256:" + h.hexdigest()


def prune_cache(keep: int = 2) -> None:
    base = cache_root() / "artifacts"
    if not base.is_dir():
        return
    for platform_dir in base.iterdir():
        versions = sorted((d for d in platform_dir.iterdir() if d.is_dir()),
                          key=lambda d: version_tuple(d.name), reverse=True)
        for old in versions[keep:]:
            shutil.rmtree(old, ignore_errors=True)


# --- verification --------------------------------------------------------------------------------
def verify_release(manifest: dict[str, Any], signature_b64: str, artefact: Path) -> Optional[str]:
    """Return an error code, or None when the release is trustworthy."""
    if manifest_problems(manifest):
        return "manifest-invalid"
    public_key = TRUSTED_KEYS.get(str(manifest.get("key_id")))
    if not public_key:
        return "signature-failed"
    if not ed25519_verify(b64url_decode(public_key), b64url_decode(signature_b64), canonical(manifest)):
        return "signature-failed"
    if manifest["platform"] != current_platform():
        return "unsupported-platform"
    if version_tuple(CLIENT_VERSION) < version_tuple(manifest["min_client"]):
        return "client-too-old"
    if manifest.get("max_client") and version_tuple(CLIENT_VERSION) > version_tuple(manifest["max_client"]):
        return "client-too-old"
    if not artefact.is_file() or artefact.stat().st_size != manifest["size"]:
        return "digest-failed"
    if digest_file(artefact) != manifest["artifact_sha256"]:
        return "digest-failed"
    return None


# --- service + download --------------------------------------------------------------------------
def request_release(key: str, channel: str, core_version: Optional[str]) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Ask the release service for a manifest, signature and short-lived URL. Sends nothing else."""
    body = json.dumps({"key": key, "client_version": CLIENT_VERSION, "platform": current_platform(),
                       "channel": channel, **({"core_version": core_version} if core_version else {})}).encode()
    req = urllib.request.Request(f"{SERVICE_URL}/download", data=body, method="POST",
                                 headers={"content-type": "application/json",
                                          "user-agent": f"presift-launcher/{CLIENT_VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=NETWORK_TIMEOUT) as response:
            return json.loads(response.read().decode()), None
    except urllib.error.HTTPError as e:
        try:
            code = json.loads(e.read().decode()).get("code", "")
        except Exception:
            code = ""
        return None, code or ("bad-key" if e.code in (401, 403) else "artifact-unavailable" if e.code == 404 else "service-unavailable")
    except Exception:
        return None, "service-unavailable"


def download(url: str, target: Path, expected_size: int) -> Optional[str]:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), suffix=".part")
    os.close(fd)                       # never hold a write handle: an open fd makes exec fail (ETXTBSY)
    tmp = Path(tmp_name)
    try:
        req = urllib.request.Request(url, headers={"user-agent": f"presift-launcher/{CLIENT_VERSION}"})
        written = 0
        with urllib.request.urlopen(req, timeout=NETWORK_TIMEOUT) as response, tmp.open("wb") as fh:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                written += len(block)
                if written > min(expected_size, MAX_ARTIFACT_BYTES):
                    return "download-failed"
                fh.write(block)
        if written != expected_size:
            return "download-failed"
        tmp.chmod(stat.S_IRWXU)
        os.replace(tmp, target)
        return None
    except Exception:
        return "download-failed"
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def attested_trial_key() -> tuple[Optional[str], Optional[str], dict[str, Any]]:
    """Exchange the job's GitHub OIDC token for a short-lived trial key. Returns (key, error_code, details)."""
    url, bearer = os.environ.get(OIDC_URL_ENV, ""), os.environ.get(OIDC_TOKEN_ENV, "")
    if not url or not bearer:
        return None, "no-oidc", {}
    sep = "&" if "?" in url else "?"
    req = urllib.request.Request(f"{url}{sep}audience={urllib.parse.quote(OIDC_AUDIENCE, safe='')}",
                                 headers={"authorization": f"bearer {bearer}", "accept": "application/json",
                                          "user-agent": f"presift-launcher/{CLIENT_VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=NETWORK_TIMEOUT) as response:
            jwt = str(json.loads(response.read().decode()).get("value", ""))
    except Exception:
        return None, "no-oidc", {}
    if jwt.count(".") != 2:
        return None, "no-oidc", {}
    body = json.dumps({"client_version": CLIENT_VERSION}).encode()
    req = urllib.request.Request(f"{SERVICE_URL}/trial/actions", data=body, method="POST",
                                 headers={"content-type": "application/json", "authorization": f"Bearer {jwt}",
                                          "user-agent": f"presift-launcher/{CLIENT_VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=NETWORK_TIMEOUT) as response:
            payload = json.loads(response.read().decode())
            key = str(payload.get("key", ""))
            return (key, None, payload) if key.startswith("PS1.") else (None, "service-unavailable", {})
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode())
        except Exception:
            payload = {}
        code = str(payload.get("code", "")) or ("bad-oidc" if e.code in (401, 403) else "service-unavailable")
        return None, code, payload
    except Exception:
        return None, "service-unavailable", {}


def ensure_release(key: str, channel: str, core_version: Optional[str]) -> tuple[Optional[Path], Optional[str], dict[str, Any]]:
    payload, error = request_release(key, channel, core_version)
    if error or not payload:
        cached = newest_cached(channel, core_version)
        if cached and error == "service-unavailable":
            return cached[0], None, cached[1]
        return None, error or "service-unavailable", {}
    manifest = payload.get("manifest") or {}
    signature = str(payload.get("manifest_sig", ""))
    slot = cache_slot(manifest) if not manifest_problems(manifest) else None
    if slot is None:
        return None, "manifest-invalid", manifest
    artefact = slot / manifest["filename"]
    if not artefact.is_file():
        problem = download(str(payload.get("url", "")), artefact, int(manifest["size"]))
        if problem:
            return None, problem, manifest
    problem = verify_release(manifest, signature, artefact)
    if problem:
        shutil.rmtree(slot, ignore_errors=True)
        return None, problem, manifest
    (slot / "manifest.json").write_bytes(canonical(manifest))
    (slot / "manifest.sig").write_text(signature, encoding="utf-8")
    slot.chmod(stat.S_IRWXU)
    return artefact, None, manifest


def newest_cached(channel: str, core_version: Optional[str]) -> Optional[tuple[Path, dict[str, Any]]]:
    """Most recent cached release that still verifies. Used only when the service is unreachable."""
    base = cache_root() / "artifacts" / current_platform()
    if not base.is_dir():
        return None
    for version_dir in sorted((d for d in base.iterdir() if d.is_dir()), key=lambda d: version_tuple(d.name), reverse=True):
        if core_version and version_dir.name != core_version:
            continue
        for slot in version_dir.iterdir():
            try:
                manifest = json.loads((slot / "manifest.json").read_text())
                signature = (slot / "manifest.sig").read_text().strip()
            except Exception:
                continue
            if channel and manifest.get("channel") != channel:
                continue
            artefact = slot / manifest.get("filename", "")
            if verify_release(manifest, signature, artefact) is None:
                return artefact, manifest
    return None


# --- entry point ----------------------------------------------------------------------------------
def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    channel = os.environ.get("PRESIFT_CHANNEL", "stable")
    core_version = os.environ.get("PRESIFT_CORE_VERSION") or None
    key = os.environ.get(KEY_ENV, "").strip()
    trial_note = ""
    if not key:
        if _fork_context():
            return fail("no-key-fork")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            key, problem, details = attested_trial_key()
            if problem:
                return fail(problem, org=str(details.get("org", "?")), ended=str(details.get("ended", "?")))
            trial_note = f"Presift evaluation for '{details.get('org')}' — ends {details.get('trial_ends')} ({PRICING_URL})"
        else:
            return fail("no-key")
    if not key.startswith("PS1.") or key.count(".") != 2:
        return fail("bad-key")
    if trial_note:
        sys.stderr.write(f"presift: {trial_note}\n")
    if current_platform() not in SUPPORTED_PLATFORMS:
        return fail("unsupported-platform", platform=current_platform())

    artefact, error, manifest = ensure_release(key, channel, core_version)
    if error or artefact is None:
        return fail(error or "service-unavailable", platform=current_platform(), channel=channel,
                    client=CLIENT_VERSION, min_client=str(manifest.get("min_client", "?")))
    prune_cache()

    import subprocess
    completed = subprocess.run([str(artefact), *argv], env={**os.environ, KEY_ENV: key})
    return completed.returncode


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
