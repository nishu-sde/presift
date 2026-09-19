"""The client stays a client: no analysis logic, no dependencies, no credentials, no stray identity.

Standard library only, so this runs anywhere Python does: `python -m unittest discover tests`.
"""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).name
TEXT_SUFFIXES = {".py", ".md", ".yml", ".yaml", ".toml", ".json", ".txt", ".sh"}

SECRETS = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{12}|ghp_[A-Za-z0-9]{20}|"
                     r"sk_live_|xox[baprs]-|aws_secret|Authorization:\s*Bearer\s+\S")
ATTRIBUTION = re.compile(r"co-authored-by|generated\s+(?:with|by)\s+(?:an?\s+)?(?:ai|llm|assistant|model)", re.I)
IDENTITY = re.compile(r"/home/[a-z]+/|/Users/[a-z]+/|C:\\Users\\|@gmail\.com|@hotmail\.com", re.I)
ALLOWED_HOSTS = {"presift.dev", "api.presift.dev", "github.com", "dev.mysql.com", "www.apache.org"}


def text_files():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True)
    names = out.stdout.split() if out.returncode == 0 else [
        str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file() and ".git/" not in str(p)]
    return [ROOT / n for n in names
            if (ROOT / n).is_file() and ((ROOT / n).suffix in TEXT_SUFFIXES or (ROOT / n).name in ("LICENSE", "NOTICE"))]


def scannable():
    return [p for p in text_files() if p.name != SELF]


class PublicBoundary(unittest.TestCase):
    def test_the_client_is_only_a_client(self):
        """No analysis, no packaging, no service implementation: one launcher, one action, docs."""
        code = [p for p in text_files() if p.suffix == ".py" and "tests/" not in str(p.relative_to(ROOT))]
        self.assertEqual([p.name for p in code], ["presift_launch.py"])
        body = (ROOT / "presift_launch.py").read_text()
        for absent in ("CREATE TABLE", "ALTER TABLE", "def analyse", "def lint", "severity"):
            self.assertNotIn(absent, body, f"the launcher looks like it analyses SQL: {absent!r}")

    def test_launcher_imports_only_the_standard_library(self):
        source = (ROOT / "presift_launch.py").read_text()
        modules = {m.split(".")[0] for m in
                   re.findall(r"^\s*(?:import|from)\s+([A-Za-z_][\w.]*)", source, re.M)}
        stdlib = {"__future__", "base64", "hashlib", "json", "os", "pathlib", "platform", "shutil",
                  "stat", "subprocess", "sys", "tempfile", "typing", "urllib"}
        self.assertLessEqual(modules, stdlib, f"non-stdlib imports: {modules - stdlib}")

    def test_no_secret_material(self):
        for path in scannable():
            self.assertIsNone(SECRETS.search(path.read_text(errors="replace")), path.name)

    def test_no_third_party_attribution_or_personal_identity(self):
        for path in scannable():
            body = path.read_text(errors="replace")
            self.assertIsNone(ATTRIBUTION.search(body), path.name)
            self.assertIsNone(IDENTITY.search(body), path.name)

    def test_only_intended_public_hosts_appear(self):
        allowed = ALLOWED_HOSTS
        for path in scannable():
            for host in re.findall(r"https?://([A-Za-z0-9.-]+)", path.read_text(errors="replace")):
                self.assertIn(host, allowed, f"{path.name} references {host}")

    def test_licence_is_the_canonical_apache_2_text_with_the_project_copyright(self):
        text = (ROOT / "LICENSE").read_text()
        self.assertIn("Apache License\n                           Version 2.0, January 2004", text)
        self.assertIn("END OF TERMS AND CONDITIONS", text)
        self.assertIn("Copyright 2026 Nishu", text)
        self.assertNotIn("[name of copyright owner]", text)
        self.assertEqual(text.count("Copyright"), 2)   # the definition in section 1 and the applied notice
        self.assertIn("Apache License, Version 2.0", (ROOT / "presift_launch.py").read_text())

    def test_public_identity_and_authorship(self):
        action = (ROOT / "action.yml").read_text()
        self.assertIn('author: "Nishu"', action)
        self.assertIn("Presift, by Nishu", (ROOT / "presift_launch.py").read_text())
        self.assertIn("Presift, by Nishu", (ROOT / "README.md").read_text())

    def test_no_release_binary_is_committed(self):
        for path in ROOT.rglob("*"):
            if path.is_file() and ".git/" not in str(path):
                self.assertLess(path.stat().st_size, 512 * 1024, f"{path.name} is unexpectedly large")
                self.assertNotIn(path.suffix, {".bin", ".so", ".exe", ".zip", ".tar", ".gz"})

    def test_action_passes_no_secret_beyond_the_key_and_fails_closed(self):
        action = (ROOT / "action.yml").read_text()
        self.assertIn("inputs.license", action)
        self.assertNotIn("secrets.", action)                      # the caller supplies it, not the action
        self.assertNotIn("pull_request_target", action)
        self.assertIn("set -euo pipefail", action)
        self.assertIn('using: "composite"', action)               # no container build, no image pull


if __name__ == "__main__":
    unittest.main()
