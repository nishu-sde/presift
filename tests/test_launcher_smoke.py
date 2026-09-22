"""The launcher's promises, checked without a network, a service or a release.

These are the guarantees a user is entitled to rely on: it refuses without a valid key, it refuses
anything it cannot verify, and it never runs a file whose bytes do not match the signed digest.
"""
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import presift_launch as L  # noqa: E402

REFUSED = 2


def clean_env(**overrides):
    keep = {k: v for k, v in os.environ.items() if not k.startswith(("PRESIFT_", "GITHUB_"))}
    keep.update(overrides)
    return keep


class Refusals(unittest.TestCase):
    def setUp(self):
        self._saved = dict(os.environ)
        os.environ.clear()
        os.environ.update(clean_env())

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved)

    def test_no_key_refuses(self):
        self.assertEqual(L.main([]), REFUSED)

    def test_malformed_key_refuses_before_any_request(self):
        os.environ[L.KEY_ENV] = "not-a-key"
        self.assertEqual(L.main([]), REFUSED)

    def test_fork_context_gets_its_own_message(self):
        os.environ.update({"GITHUB_EVENT_NAME": "pull_request", "GITHUB_HEAD_REF": "patch-1",
                           "GITHUB_REPOSITORY": "someone-else/repo", "GITHUB_REPOSITORY_OWNER": "us"})
        self.assertTrue(L._fork_context())
        self.assertIn("fork", L.MESSAGES["no-key-fork"])

    def test_messages_never_contain_the_key(self):
        self.assertEqual(L.redact("key=PS1.abc.def", "PS1.abc.def"), "key=***")


class Verification(unittest.TestCase):
    """No trusted key is embedded until the first public release, so everything must be refused."""

    def manifest(self, artefact: Path):
        data = artefact.read_bytes()
        return {"schema": "presift.release/1", "product": "presift", "version": "0.0.1",
                "platform": L.current_platform(), "filename": artefact.name, "channel": "stable",
                "artifact_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                "size": len(data), "min_client": "1.0.0", "key_id": "presift-release-1"}

    def test_unsigned_release_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            art = Path(d) / "presift-0.0.1"
            art.write_bytes(b"not the real thing")
            self.assertEqual(L.verify_release(self.manifest(art), "AAAA", art), "signature-failed")

    def test_malformed_manifest_is_refused_before_any_signature_work(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            art = Path(d) / "presift-0.0.1"
            art.write_bytes(b"x")
            m = self.manifest(art)
            m["artifact_sha256"] = "sha256:short"
            self.assertEqual(L.verify_release(m, "AAAA", art), "manifest-invalid")

    def test_manifest_cannot_name_a_path(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            art = Path(d) / "presift-0.0.1"
            art.write_bytes(b"x")
            m = self.manifest(art)
            m["filename"] = "../../etc/passwd"
            self.assertIn("filename", L.manifest_problems(m))

    def test_signature_check_rejects_garbage_without_raising(self):
        self.assertFalse(L.ed25519_verify(b"", b"", b"message"))
        self.assertFalse(L.ed25519_verify(b"\x00" * 32, b"\x01" * 64, b"message"))

    def test_canonical_form_is_byte_stable(self):
        a = L.canonical({"b": 2, "a": 1})
        b = L.canonical({"a": 1, "b": 2})
        self.assertEqual(a, b)
        self.assertEqual(a, b'{"a":1,"b":2}')

    def test_trusted_keys_are_public_halves_only(self):
        for value in L.TRUSTED_KEYS.values():
            self.assertEqual(len(L.b64url_decode(value)), 32)


class AttestedEvaluation(unittest.TestCase):
    """The evaluation is requested only in GitHub Actions, only without a supplied key, and never touches the network first."""

    def setUp(self):
        self._saved = dict(os.environ); os.environ.clear(); os.environ.update(clean_env())
        self.calls = []
        self._orig = L.urllib.request.urlopen
        L.urllib.request.urlopen = lambda *a, **k: self.calls.append(a) or (_ for _ in ()).throw(OSError("no network in tests"))

    def tearDown(self):
        L.urllib.request.urlopen = self._orig; os.environ.clear(); os.environ.update(self._saved)

    def test_missing_id_token_permission_fails_closed_before_any_request(self):
        os.environ["GITHUB_ACTIONS"] = "true"
        self.assertEqual(L.main(["check", "x.sql"]), REFUSED); self.assertEqual(self.calls, [])

    def test_fork_pull_request_never_requests_a_token(self):
        os.environ.update({"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_HEAD_REF": "x",
                           "GITHUB_REPOSITORY": "someone-else/repo", "GITHUB_REPOSITORY_OWNER": "us",
                           L.OIDC_URL_ENV: "stub-never-contacted", L.OIDC_TOKEN_ENV: "t"})
        self.assertEqual(L.main(["check", "x.sql"]), REFUSED); self.assertEqual(self.calls, [])

    def test_outside_actions_no_evaluation_is_requested(self):
        os.environ.update({L.OIDC_URL_ENV: "stub-never-contacted", L.OIDC_TOKEN_ENV: "t"})
        self.assertEqual(L.main(["check", "x.sql"]), REFUSED); self.assertEqual(self.calls, [])

    def test_supplied_key_takes_precedence(self):
        os.environ.update({"GITHUB_ACTIONS": "true", L.KEY_ENV: "PS1.x.y", L.OIDC_URL_ENV: "stub-never-contacted", L.OIDC_TOKEN_ENV: "t"})
        L.main(["check", "x.sql"])
        self.assertTrue(all("oidc" not in str(getattr(a[0], "full_url", a[0])) for a in self.calls))

    def test_audience_is_exactly_the_production_api(self):
        self.assertEqual(L.OIDC_AUDIENCE, "https://api.presift.dev")
        self.assertEqual(L.SERVICE_URL, "https://api.presift.dev")


class Contract(unittest.TestCase):
    def test_supported_platforms_are_explicit(self):
        self.assertEqual(L.SUPPORTED_PLATFORMS, ("linux-x86_64",))

    def test_every_error_code_has_a_message(self):
        for code in ("no-key", "no-key-fork", "no-oidc", "bad-oidc", "oidc-expired", "trial-expired", "paid-expired",
                     "bad-key", "unsupported-platform", "artifact-unavailable",
                     "signature-failed", "digest-failed", "download-failed", "service-unavailable",
                     "client-too-old", "manifest-invalid"):
            self.assertIn(code, L.MESSAGES)

    def test_documented_codes_match_the_implementation(self):
        documented = (ROOT / "docs" / "errors.md").read_text()
        for code in L.MESSAGES:
            self.assertIn(f"`{code}`", documented)

    def test_request_sends_only_the_four_documented_fields(self):
        sent = {}

        def fake_urlopen(req, timeout=None):
            sent.update(json.loads(req.data.decode()))
            raise OSError("no network in tests")

        original = L.urllib.request.urlopen
        L.urllib.request.urlopen = fake_urlopen
        try:
            L.request_release("PS1.a.b", "stable", None)
        finally:
            L.urllib.request.urlopen = original
        self.assertEqual(set(sent), {"key", "client_version", "platform", "channel"})


if __name__ == "__main__":
    unittest.main()
