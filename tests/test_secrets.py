import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis.collectors.identity.secrets import _private_blocks, audit, fingerprint, scan_file


class SecretScannerSyntaxTests(unittest.TestCase):
    def test_audit_does_not_infer_volume_encryption_or_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("jarvis.collectors.identity.secrets.run.walk", return_value=["/test/key", "/test/key"]), \
                 patch("jarvis.collectors.identity.secrets.run.scan_file", return_value=[
                     ("private key block (encrypted)", "synthetic-key", 1, "low")]), \
                 patch("jarvis.collectors.identity.secrets.run._other_humans", return_value=[]), \
                 patch("jarvis.collectors.identity.secrets.run._world_readable", return_value=False), \
                 patch("jarvis.collectors.identity.secrets.run._git_tracked", return_value=(False, "")), \
                 patch("jarvis.collectors.identity.secrets.run.os.path.expanduser", return_value=directory):
                findings = audit(roots=[directory], deep=True)
        key = next(f for f in findings if "private key block" in f["title"])
        self.assertNotIn("plaintext", key["title"])
        self.assertNotIn("more location", key["title"])
        self.assertNotIn("disk is not encrypted", key["detail"])
        self.assertIn("has not been verified", key["detail"])
        self.assertNotIn("synthetic-key", key["detail"])

    def test_private_key_identity_uses_body_and_ignores_wrapping(self):
        def block(body):
            return f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
        first = list(_private_blocks(block("YWJj\nZGVm")))[0]
        wrapped = list(_private_blocks(block("YWJjZGVm")))[0]
        other = list(_private_blocks(block("Z2hpamts")))[0]
        self.assertEqual(fingerprint(first[1]), fingerprint(wrapped[1]))
        self.assertNotEqual(fingerprint(first[1]), fingerprint(other[1]))
        self.assertEqual(first[0], "private key block (unencrypted)")

    def test_encrypted_pem_is_not_reported_as_plaintext(self):
        hit = list(_private_blocks(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nYWJj\n"
            "-----END ENCRYPTED PRIVATE KEY-----"))[0]
        self.assertEqual(hit[0], "private key block (encrypted)")
        self.assertEqual(hit[3], "low")

    def test_header_alone_is_not_a_private_key(self):
        self.assertEqual(self.scan("key.pem", "-----BEGIN PRIVATE KEY-----"), [])

    def test_openssh_cipher_classification(self):
        import base64
        for cipher, expected in ((b"none", "unencrypted"), (b"aes256-ctr", "encrypted")):
            raw = b"openssh-key-v1\0" + len(cipher).to_bytes(4, "big") + cipher
            body = base64.b64encode(raw).decode()
            hit = list(_private_blocks(
                f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n"
                "-----END OPENSSH PRIVATE KEY-----"))[0]
            self.assertEqual(hit[0], f"private key block ({expected})")

    def scan(self, name, text):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            return [(kind, line) for kind, _value, line, _sev in scan_file(path)]

    def test_quoted_secret_literal_is_detected(self):
        hits = self.scan("settings.ts", 'const config = { apiKey: "a8F2kL9xQ4mN7pR3vT6yW1zC" };\n')
        self.assertEqual(hits, [("generic secret assignment", 1)])

    def test_runtime_expressions_are_not_secret_literals(self):
        hits = self.scan(
            "settings.ts",
            "const config = {\n"
            "  password: credentials.password,\n"
            "  input_tokens: completed.inputTokens,\n"
            "  signing_key: settings.keyForToken(token),\n"
            "};\n",
        )
        self.assertEqual(hits, [])

    def test_environment_variable_names_are_not_values(self):
        hits = self.scan(
            "provider.ts",
            'const config = { webhookSecretEnv: "CARD_ACQUIRER_WEBHOOK_SECRET" };\n',
        )
        self.assertEqual(hits, [])

    def test_storage_namespace_is_not_a_token(self):
        hits = self.scan("oidc.ts", 'const tokenKey = "product.oidc_access.token";\n')
        self.assertEqual(hits, [])

    def test_bare_env_value_is_detected(self):
        hits = self.scan(".env", "SERVICE_SECRET=a8F2kL9xQ4mN7pR3vT6yW1zC\n")
        self.assertEqual(hits, [("generic secret assignment", 1)])

    def test_database_url_placeholder_is_not_a_credential(self):
        hits = self.scan(
            "architecture.md",
            "DATABASE_URL=postgresql://user:password@host:5432/database\n",
        )
        self.assertEqual(hits, [])


class WalkSkipTests(unittest.TestCase):
    def test_a_skipped_directory_is_skipped_itself_not_only_below_it(self):
        from jarvis.collectors.identity.secrets import run
        with tempfile.TemporaryDirectory() as root:
            for rel in (".claude/paste-cache/a.txt", "node_modules/b.env", "app/.env",
                        ".nvm/share/man/man7/config.7"):
                path = os.path.join(root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as handle:
                    handle.write("x")
            walked = sorted(os.path.relpath(p, root) for p in run.walk([root]))
        self.assertEqual(walked, ["app/.env"])


if __name__ == "__main__":
    unittest.main()


class DesignatedStoreTests(unittest.TestCase):
    """A token in its own tool's owner-only store is inventory; any copy
    elsewhere, a loose mode, or another account keeps it critical."""

    def run_audit(self, home, files, others=()):
        with patch("jarvis.collectors.identity.secrets.run.walk", return_value=files), \
             patch("jarvis.collectors.identity.secrets.run.scan_file",
                   side_effect=lambda p: [("GitHub token", "gho_same", 4, "critical")]), \
             patch("jarvis.collectors.identity.secrets.run._other_humans", return_value=list(others)), \
             patch("jarvis.collectors.identity.secrets.run._git_tracked", return_value=(False, "")), \
             patch("jarvis.collectors.identity.secrets.run.os.path.expanduser", return_value=home):
            return [f for f in audit(roots=[home], deep=True) if "GitHub token" in f["title"]]

    def store(self, home, mode=0o600):
        path = os.path.join(home, ".config", "gh", "hosts.yml")
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as fh:
            fh.write("x")
        os.chmod(path, mode)
        return path

    def test_owner_only_tool_store_is_advisory_and_named(self):
        with tempfile.TemporaryDirectory() as home:
            out = self.run_audit(home, [self.store(home)])
        self.assertEqual([(f["severity"], f["title"]) for f in out],
                         [("low", "GitHub token in GitHub CLI's credential store")])

    def test_wrangler_oauth_file_is_a_tool_store(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, ".config", ".wrangler", "config", "default.toml")
            os.makedirs(os.path.dirname(path))
            with open(path, "w") as handle:
                handle.write("x")
            os.chmod(path, 0o600)
            out = self.run_audit(home, [path])
        self.assertEqual([(f["severity"], f["title"]) for f in out],
                         [("low", "GitHub token in Wrangler's credential store")])

    def test_copy_outside_the_store_stays_critical(self):
        with tempfile.TemporaryDirectory() as home:
            leak = os.path.join(home, "history.jsonl")
            open(leak, "w").close()
            out = self.run_audit(home, [self.store(home), leak])
        self.assertEqual([f["severity"] for f in out], ["critical"])

    def test_loose_mode_or_other_accounts_stay_critical(self):
        with tempfile.TemporaryDirectory() as home:
            self.assertEqual([f["severity"] for f in self.run_audit(
                home, [self.store(home, 0o640)])], ["critical"])
        with tempfile.TemporaryDirectory() as home:
            out = self.run_audit(home, [self.store(home)], others=["guest"])
            self.assertEqual([f["severity"] for f in out], ["critical"])


class ProjectEnvironmentTests(unittest.TestCase):
    def audit_file(self, path, home):
        with patch("jarvis.collectors.identity.secrets.run.walk", return_value=[path]), \
             patch("jarvis.collectors.identity.secrets.run.scan_file",
                   return_value=[("generic secret assignment", "synthetic-secret", 1,
                                  "medium")]), \
             patch("jarvis.collectors.identity.secrets.run._other_humans", return_value=[]), \
             patch("jarvis.collectors.identity.secrets.run.os.path.expanduser",
                   return_value=home):
            return next(f for f in audit(roots=[home], deep=True)
                        if f["title"].startswith("generic secret assignment"))

    def repo(self, home, ignored=True, mode=0o600):
        import subprocess
        root = os.path.join(home, "app")
        os.mkdir(root)
        subprocess.run(["git", "-C", root, "init", "-q"], check=True)
        if ignored:
            with open(os.path.join(root, ".gitignore"), "w") as handle:
                handle.write(".env*\n")
        path = os.path.join(root, ".env.local")
        with open(path, "w") as handle:
            handle.write("x")
        os.chmod(path, mode)
        return root, path

    def test_private_git_ignored_project_env_is_advisory(self):
        with tempfile.TemporaryDirectory() as home:
            _root, path = self.repo(home)
            finding = self.audit_file(path, home)
        self.assertEqual(finding["severity"], "low")
        self.assertIn("private project environment file", finding["title"])
        self.assertNotIn("synthetic-secret", finding["detail"])

    def test_unignored_or_loose_project_env_remains_actionable(self):
        for ignored, mode in ((False, 0o600), (True, 0o644)):
            with self.subTest(ignored=ignored, mode=oct(mode)):
                with tempfile.TemporaryDirectory() as home:
                    _root, path = self.repo(home, ignored=ignored, mode=mode)
                    finding = self.audit_file(path, home)
                self.assertEqual(finding["severity"], "medium")

    def test_private_local_app_without_git_is_advisory(self):
        with tempfile.TemporaryDirectory() as home:
            project = os.path.join(home, "app")
            os.mkdir(project)
            open(os.path.join(project, "requirements.txt"), "w").close()
            os.mkdir(os.path.join(project, ".git"))  # copied app; not a repo
            path = os.path.join(project, ".env")
            with open(path, "w") as handle:
                handle.write("x")
            os.chmod(path, 0o600)
            finding = self.audit_file(path, home)
        self.assertEqual(finding["severity"], "low")

    def test_broken_git_metadata_cannot_use_local_app_fallback(self):
        with tempfile.TemporaryDirectory() as home:
            project = os.path.join(home, "app")
            os.mkdir(project)
            open(os.path.join(project, "package.json"), "w").close()
            os.mkdir(os.path.join(project, ".git"))
            open(os.path.join(project, ".git", "HEAD"), "w").close()
            path = os.path.join(project, ".env")
            with open(path, "w") as handle:
                handle.write("x")
            os.chmod(path, 0o600)
            finding = self.audit_file(path, home)
        self.assertEqual(finding["severity"], "medium")

    def test_tracked_env_is_critical_even_with_ignore_rule(self):
        import subprocess
        with tempfile.TemporaryDirectory() as home:
            root, path = self.repo(home)
            subprocess.run(["git", "-C", root, "add", "-f", "--", path], check=True)
            finding = self.audit_file(path, home)
        self.assertEqual(finding["severity"], "critical")

    def test_copy_outside_project_prevents_advisory_classification(self):
        with tempfile.TemporaryDirectory() as home:
            _root, path = self.repo(home)
            copy = os.path.join(home, "loose.txt")
            with open(copy, "w") as handle:
                handle.write("x")
            with patch("jarvis.collectors.identity.secrets.run.walk",
                       return_value=[path, copy]), \
                 patch("jarvis.collectors.identity.secrets.run.scan_file",
                       return_value=[("generic secret assignment", "same-secret", 1,
                                      "medium")]), \
                 patch("jarvis.collectors.identity.secrets.run._other_humans",
                       return_value=[]), \
                 patch("jarvis.collectors.identity.secrets.run.os.path.expanduser",
                       return_value=home):
                finding = next(f for f in audit(roots=[home], deep=True)
                               if f["title"].startswith("generic secret assignment"))
        self.assertEqual(finding["severity"], "medium")
