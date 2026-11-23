"""Vulnerabilities in the application code a server runs (ARGUS-SERVER.md W12).

Dependency CVEs and malicious packages from lockfiles matched against the
public OSV dumps locally, risky code patterns, credentials in code trees,
writable code and .env/.git under a web root, and bandit/semgrep only when the
operator already has them. Every unreadable or unscanned part is stated,
never reported as clean.
"""

import io
import json
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from jarvis.collectors import appcode
from jarvis.collectors.appcode import deps, discover, lockfiles, rules, tools
from jarvis.core import mechanisms, osvindex
from jarvis.intel import osv

GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _write(root, rel, text, mode=None):
    path = Path(root) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if mode is not None:
        os.chmod(path, mode)
    return str(path)


def _entry(id_, *, ranges=(), versions=(), aliases=(), severity="", malicious=False):
    return {"id": id_, "aliases": list(aliases), "severity": severity, "summary": "s",
            "ranges": [list(r) for r in ranges], "versions": list(versions),
            "malicious": malicious}


# --- versions ---------------------------------------------------------------

class VersionOrder(unittest.TestCase):
    ASCENDING = ["0.9", "1.0.0.dev1", "1.0.0-alpha", "1.0.0a1", "1.0.0-beta.2", "1.0.0rc1",
                 "1.0.0", "1.0.0.post1", "1.0.1", "1.2", "1.10", "2.0.0-rc.1", "2.0.0", "v2.0.1",
                 "10.0"]

    def test_known_orderings(self):
        cases = [("1.0", "1.0.0", 0), ("v1.2.3", "1.2.3", 0), ("1.2.3+build5", "1.2.3", 0),
                 ("1.9", "1.10", -1), ("1.0.0-rc1", "1.0.0", -1), ("1.0.post1", "1.0.1", -1),
                 ("4.17.20", "4.17.21", -1), ("2.0.0.RELEASE", "2.0.0", 0),
                 ("1.0-SNAPSHOT", "1.0", -1), ("1.0.0.beta", "1.0.0", -1)]
        for a, b, want in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual(osvindex.compare(a, b), want)
                self.assertEqual(osvindex.compare(b, a), -want)

    def test_total_order_over_samples(self):
        vs = self.ASCENDING
        for i, a in enumerate(vs):
            for j, b in enumerate(vs):
                with self.subTest(a=a, b=b):
                    self.assertEqual(osvindex.compare(a, b), (i > j) - (i < j))

    def test_garbage_never_raises(self):
        for v in ("", "-", "...", "abc", "1..2", "x" * 500, "1.0-☃"):
            osvindex.compare(v, "1.0")


class Affected(unittest.TestCase):
    def test_introduced_fixed(self):
        e = _entry("GHSA-1", ranges=[("0", "4.17.21", None)])
        self.assertTrue(osvindex.affected("4.17.20", e))
        self.assertFalse(osvindex.affected("4.17.21", e))
        self.assertFalse(osvindex.affected("5.0.0", e))

    def test_last_affected_is_inclusive(self):
        e = _entry("GHSA-2", ranges=[("1.0", None, "1.4")])
        self.assertTrue(osvindex.affected("1.4", e))
        self.assertFalse(osvindex.affected("1.4.1", e))
        self.assertFalse(osvindex.affected("0.9", e))

    def test_two_ranges(self):
        e = _entry("GHSA-3", ranges=[("1.0", "1.2.5", None), ("2.0", "2.0.3", None)])
        self.assertTrue(osvindex.affected("2.0.1", e))
        self.assertFalse(osvindex.affected("1.5", e))

    def test_explicit_versions_win(self):
        e = _entry("PYSEC-1", versions=["2.31.0"], ranges=[])
        self.assertTrue(osvindex.affected("2.31.0", e))
        self.assertFalse(osvindex.affected("2.32.0", e))

    def test_open_range_means_every_later_version(self):
        self.assertTrue(osvindex.affected("9.9", _entry("MAL-1", ranges=[("0", None, None)])))

    def test_names_are_normalised_per_ecosystem(self):
        self.assertEqual(osvindex.normalise("PyPI", "Django_REST.framework"), "django-rest-framework")
        self.assertEqual(osvindex.normalise("Packagist", "Symfony/HTTP-Kernel"), "symfony/http-kernel")
        self.assertEqual(osvindex.normalise("npm", "@Babel/core"), "@babel/core")
        self.assertEqual(osvindex.normalise("crates.io", "Serde"), "Serde")


# --- lockfiles --------------------------------------------------------------

class Lockfiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _parse(self, name, text):
        return sorted(lockfiles.parse(_write(self.tmp, name, text)))

    def test_requirements_pins_only(self):
        got = self._parse("requirements.txt", "Django==4.2.1\nrequests>=2\n# x==1\n"
                          "flask == 2.0.0 ; python_version > '3'\n-e git+https://x\n")
        self.assertEqual(got, [("PyPI", "django", "4.2.1"), ("PyPI", "flask", "2.0.0")])

    def test_package_lock_v3_and_v1(self):
        v3 = {"lockfileVersion": 3, "packages": {"": {"name": "app"},
              "node_modules/lodash": {"version": "4.17.20"},
              "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"},
              "node_modules/linked": {"link": True}}}
        self.assertEqual(self._parse("package-lock.json", json.dumps(v3)),
                         [("npm", "@scope/b", "1.0.0"), ("npm", "lodash", "4.17.20")])
        v1 = {"lockfileVersion": 1, "dependencies": {"x": {"version": "1.0.0", "dependencies":
              {"y": {"version": "2.0.0"}}}}}
        self.assertEqual(self._parse("npm-shrinkwrap.json", json.dumps(v1)),
                         [("npm", "x", "1.0.0"), ("npm", "y", "2.0.0")])

    def test_yarn_classic_and_berry(self):
        classic = ('"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.22.5"\n'
                   'lodash@^4.17.0:\n  version "4.17.20"\n')
        self.assertEqual(self._parse("yarn.lock", classic),
                         [("npm", "@babel/core", "7.22.5"), ("npm", "lodash", "4.17.20")])
        berry = '"lodash@npm:^4.17.0":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n'
        self.assertEqual(self._parse("sub/yarn.lock", berry), [("npm", "lodash", "4.17.21")])

    def test_pnpm(self):
        text = "lockfileVersion: '9.0'\npackages:\n  /lodash@4.17.20:\n    resolution: {}\n" \
               "  '@scope/pkg@1.2.3':\n    resolution: {}\n"
        self.assertEqual(self._parse("pnpm-lock.yaml", text),
                         [("npm", "@scope/pkg", "1.2.3"), ("npm", "lodash", "4.17.20")])

    def test_poetry_uv_cargo(self):
        toml = '[[package]]\nname = "Jinja2"\nversion = "3.1.2"\n\n[[package]]\nname = "x"\nversion = "1"\n'
        self.assertEqual(self._parse("poetry.lock", toml), [("PyPI", "jinja2", "3.1.2"), ("PyPI", "x", "1")])
        self.assertEqual(self._parse("uv.lock", toml), [("PyPI", "jinja2", "3.1.2"), ("PyPI", "x", "1")])
        self.assertEqual(self._parse("Cargo.lock", toml), [("crates.io", "Jinja2", "3.1.2"),
                                                          ("crates.io", "x", "1")])

    def test_pipfile_composer_gemfile_gomod_pom(self):
        self.assertEqual(self._parse("Pipfile.lock", json.dumps(
            {"default": {"urllib3": {"version": "==1.26.0"}}, "develop": {"pytest": {"version": "==7.0"}}})),
            [("PyPI", "pytest", "7.0"), ("PyPI", "urllib3", "1.26.0")])
        self.assertEqual(self._parse("composer.lock", json.dumps(
            {"packages": [{"name": "Monolog/monolog", "version": "v2.9.1"}], "packages-dev": []})),
            [("Packagist", "monolog/monolog", "2.9.1")])
        gem = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n      x (>= 1)\n" \
              "    nokogiri (1.13.0-x86_64-linux)\n\nPLATFORMS\n"
        self.assertEqual(self._parse("Gemfile.lock", gem),
                         [("RubyGems", "nokogiri", "1.13.0"), ("RubyGems", "rack", "2.2.3")])
        gomod = "module x\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/net v0.7.0\n\tgithub.com/a/b v1.0.0+incompatible // indirect\n)\nrequire github.com/c/d v1.2.0\n"
        self.assertEqual(self._parse("go.mod", gomod),
                         [("Go", "github.com/a/b", "1.0.0"), ("Go", "github.com/c/d", "1.2.0"),
                          ("Go", "golang.org/x/net", "0.7.0")])
        pom = ("<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId>"
               "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>"
               "<dependency><groupId>g</groupId><artifactId>a</artifactId><version>${v}</version>"
               "</dependency></dependencies></project>")
        self.assertEqual(self._parse("pom.xml", pom),
                         [("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")])

    def test_venv_dist_info(self):
        venv = Path(self.tmp) / "venv"
        sp = venv / "lib" / "python3.12" / "site-packages"
        (sp / "Flask-2.0.0.dist-info").mkdir(parents=True)
        (sp / "jinja2-3.1.2.dist-info").mkdir()
        (sp / "notapkg").mkdir()
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
        self.assertEqual(sorted(lockfiles.venv_packages(str(venv))),
                         [("PyPI", "flask", "2.0.0"), ("PyPI", "jinja2", "3.1.2")])

    def test_hostile_input_is_bounded_not_fatal(self):
        self.assertEqual(self._parse("package-lock.json", "{not json"), [])
        self.assertEqual(self._parse("Cargo.lock", "[[[["), [])
        big = _write(self.tmp, "big/requirements.txt", "a==1\n" * (lockfiles.MAX_BYTES // 4))
        self.assertEqual(lockfiles.parse(big), [])


# --- the OSV download -------------------------------------------------------

def _dump(entries):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as zf:
        for e in entries:
            zf.writestr(f"{e['id']}.json", json.dumps(e))
    return raw.getvalue()


def _osv(id_, eco, name, events=None, versions=None, aliases=(), sev=None, withdrawn=False):
    aff = {"package": {"ecosystem": eco, "name": name}}
    if events is not None:
        aff["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
    if versions is not None:
        aff["versions"] = versions
    doc = {"id": id_, "aliases": list(aliases), "summary": "x" * 400, "affected": [aff]}
    if sev:
        doc["database_specific"] = {"severity": sev}
    if withdrawn:
        doc["withdrawn"] = "2024-01-01T00:00:00Z"
    return doc


class OsvDump(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_parse_keeps_only_inventory_names(self):
        path = os.path.join(self.tmp, "PyPI.zip")
        Path(path).write_bytes(_dump([
            _osv("PYSEC-1", "PyPI", "Django", [{"introduced": "0"}, {"fixed": "4.2.2"}],
                 aliases=["CVE-2023-1"], sev="HIGH"),
            _osv("PYSEC-2", "PyPI", "other", [{"introduced": "0"}]),
            _osv("PYSEC-3", "PyPI", "django", [{"introduced": "0"}], withdrawn=True),
            _osv("GIT-1", "PyPI", "django", None)]))
        got = osv.parse_dump(path, "PyPI", {"django"})
        self.assertEqual(list(got), ["django"])
        [e] = got["django"]
        self.assertEqual((e["id"], e["aliases"], e["severity"], e["ranges"]),
                         ("PYSEC-1", ["CVE-2023-1"], "HIGH", [["0", "4.2.2", None]]))
        self.assertLessEqual(len(e["summary"]), osv.MAX_SUMMARY)

    def test_malicious_package_entries_are_marked(self):
        path = os.path.join(self.tmp, "npm.zip")
        Path(path).write_bytes(_dump([_osv("MAL-2024-1", "npm", "evil-pkg", [{"introduced": "0"}])]))
        self.assertTrue(osv.parse_dump(path, "npm", {"evil-pkg"})["evil-pkg"][0]["malicious"])

    def test_one_malformed_advisory_does_not_fail_the_ecosystem(self):
        path = os.path.join(self.tmp, "npm.zip")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("DEEP.json", "[" * 100000)
            zf.writestr("BADAFF.json", json.dumps({"id": "X-1", "affected": [1, "x"]}))
            zf.writestr("BADRANGE.json", json.dumps({"id": "X-2", "affected": [
                {"package": {"ecosystem": "npm", "name": "evil-pkg"}, "ranges": [7]}]}))
            zf.writestr("GOOD.json", json.dumps(_osv("MAL-2024-1", "npm", "evil-pkg", [{"introduced": "0"}])))
        got = osv.parse_dump(path, "npm", {"evil-pkg"})
        self.assertEqual([e["id"] for e in got["evil-pkg"]], ["MAL-2024-1"])

    def test_oversized_member_is_refused(self):
        path = os.path.join(self.tmp, "npm.zip")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("BIG.json", b" " * (osv.MAX_MEMBER + 1))
        with self.assertRaises(ValueError):
            osv.parse_dump(path, "npm", {"x"})


class OsvRefresh(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        osvindex.write_json(os.path.join(self.root, "inventory.json"), {"packages": [
            {"eco": "PyPI", "name": "django", "version": "4.2.1", "path": "/srv/a/requirements.txt",
             "project": "/srv/a"}]})

    def test_downloads_only_ecosystems_present_and_writes_index(self):
        fetched = []

        def download(url, dest, max_bytes, timeout):
            fetched.append(url)
            Path(dest).write_bytes(_dump([_osv("PYSEC-1", "PyPI", "django",
                                                [{"introduced": "0"}, {"fixed": "4.2.2"}])]))

        findings = osv.refresh(download=download, root=self.root, now=1000)
        self.assertEqual(fetched, [osv.DUMP_URL.format(eco="PyPI")])
        index = osvindex.load(os.path.join(self.root, "index.json"))
        self.assertEqual(index["ecosystems"]["PyPI"]["packages"]["django"][0]["id"], "PYSEC-1")
        self.assertEqual(index["ecosystems"]["PyPI"]["fetched_at"], 1000)
        self.assertEqual([f["severity"] for f in findings], ["ok"])
        self.assertEqual([p for p in os.listdir(self.root) if p.endswith((".zip", ".part"))], [])

    def test_failed_download_keeps_last_good_copy(self):
        def good(url, dest, max_bytes, timeout):
            Path(dest).write_bytes(_dump([_osv("PYSEC-1", "PyPI", "django", [{"introduced": "0"}])]))

        def bad(url, dest, max_bytes, timeout):
            Path(dest).write_bytes(b"partial")
            raise OSError("connection reset")

        osv.refresh(download=good, root=self.root, now=1000)
        findings = osv.refresh(download=bad, root=self.root, now=2000)
        index = osvindex.load(os.path.join(self.root, "index.json"))
        self.assertEqual(index["ecosystems"]["PyPI"]["fetched_at"], 1000)
        self.assertIn("PYSEC-1", json.dumps(index))
        self.assertEqual([f["severity"] for f in findings], ["low"])
        self.assertIn("could not be refreshed", findings[0]["title"])
        self.assertEqual([p for p in os.listdir(self.root) if p.endswith((".zip", ".part"))], [])

    def test_no_inventory_downloads_nothing(self):
        os.unlink(os.path.join(self.root, "inventory.json"))
        findings = osv.refresh(download=lambda *a: self.fail("downloaded"), root=self.root)
        self.assertEqual(findings[0]["severity"], "low")

    def test_download_respects_byte_cap(self):
        class Resp(io.BytesIO):
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        dest = os.path.join(self.root, "x.part")
        with mock.patch("urllib.request.urlopen", return_value=Resp(b"a" * 5000)):
            with self.assertRaises(ValueError):
                osv._download("https://example.invalid/x", dest, max_bytes=1000, timeout=5)


# --- dependency judgement ----------------------------------------------------

def _inv(eco, name, version, project="/srv/shop"):
    return {"eco": eco, "name": name, "version": version, "path": f"{project}/lock", "project": project}


def _index(eco, packages, fetched_at=1000):
    return {"ecosystems": {eco: {"fetched_at": fetched_at, "packages": packages}}}


class DependencyFindings(unittest.TestCase):
    def test_malicious_package_is_critical(self):
        idx = _index("npm", {"evil": [_entry("MAL-2024-9", ranges=[("0", None, None)], malicious=True)]})
        out = deps.judge([_inv("npm", "evil", "1.0.0")], idx, kev=set(), now=2000)
        crit = [f for f in out if f["severity"] == "critical"]
        self.assertEqual(len(crit), 1)
        self.assertIn("evil", crit[0]["title"])
        self.assertIn("MAL-2024-9", crit[0]["detail"])

    def test_kev_dependency_is_high_and_rest_aggregated_per_project(self):
        idx = _index("Maven", {"org.apache.logging.log4j:log4j-core": [
            _entry("GHSA-jfh8", ranges=[("2.0", "2.15.0", None)], aliases=["CVE-2021-44228"],
                   severity="CRITICAL")]})
        idx["ecosystems"]["PyPI"] = {"fetched_at": 1000, "packages": {
            "django": [_entry("PYSEC-1", ranges=[("0", "4.2.2", None)], severity="HIGH")],
            "jinja2": [_entry("PYSEC-2", ranges=[("0", "3.1.3", None)], severity="MODERATE")]}}
        inv = [_inv("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
               _inv("PyPI", "django", "4.2.1"), _inv("PyPI", "jinja2", "3.1.2"),
               _inv("PyPI", "jinja2", "3.1.2", project="/srv/blog")]
        out = deps.judge(inv, idx, kev={"CVE-2021-44228"}, now=2000)
        by = {(f["severity"], f["where"]) for f in out}
        self.assertIn(("high", "/srv/shop"), by)
        self.assertIn(("medium", "/srv/shop"), by)     # django HIGH advisory present
        self.assertIn(("low", "/srv/blog"), by)        # only a MODERATE advisory
        shop = [f for f in out if f["where"] == "/srv/shop" and f["severity"] == "medium"][0]
        self.assertIn("django 4.2.1", shop["detail"])
        self.assertIn("4.2.2", shop["detail"])

    def test_fixed_versions_are_quiet_and_say_what_was_checked(self):
        idx = _index("PyPI", {"django": [_entry("PYSEC-1", ranges=[("0", "4.2.2", None)])]})
        out = deps.judge([_inv("PyPI", "django", "4.2.2")], idx, kev=set(), now=2000)
        self.assertEqual([f["severity"] for f in out], ["ok"])
        self.assertIn("1 dependencies", out[0]["detail"])

    def test_missing_data_is_never_clean(self):
        out = deps.judge([_inv("Go", "golang.org/x/net", "0.7.0")], None, kev=set(), now=2000)
        self.assertEqual([f["severity"] for f in out], ["low"])
        self.assertNotIn("ok", {f["severity"] for f in out})
        idx = _index("PyPI", {})
        out = deps.judge([_inv("Go", "golang.org/x/net", "0.7.0")], idx, kev=set(), now=2000)
        self.assertEqual([f["severity"] for f in out], ["low"])
        self.assertIn("Go", out[0]["detail"])

    def test_stale_data_is_stated(self):
        idx = _index("PyPI", {}, fetched_at=0)
        out = deps.judge([_inv("PyPI", "x", "1")], idx, kev=set(), now=10 * 86400)
        self.assertTrue(any("old" in f["title"] for f in out))


# --- code rules -------------------------------------------------------------

class CodeRules(unittest.TestCase):
    def ids(self, text, ext):
        return {(r, tainted) for r, _line, tainted in rules.scan_text(text, ext)}

    def test_python(self):
        self.assertIn(("eval-input", True), self.ids("x = eval(request.args['q'])\n", ".py"))
        self.assertIn(("shell-exec", False), self.ids("subprocess.run(cmd, shell=True)\n", ".py"))
        self.assertIn(("sql-format", True), self.ids(
            'cur.execute(f"SELECT * FROM u WHERE id={request.args[\'id\']}")\n', ".py"))
        self.assertIn(("deserialise", False), self.ids("obj = pickle.loads(blob)\n", ".py"))
        self.assertIn(("deserialise", False), self.ids("yaml.load(fh)\n", ".py"))
        self.assertIn(("tls-off", False), self.ids("requests.get(u, verify=False)\n", ".py"))
        self.assertIn(("debug-on", False), self.ids("app.run(host='0.0.0.0', debug=True)\n", ".py"))

    def test_safe_python_is_quiet(self):
        safe = ("cur.execute('SELECT * FROM u WHERE id=%s', (uid,))\n"
                "yaml.load(fh, Loader=yaml.SafeLoader)\nsubprocess.run(['ls', path])\n"
                "# eval(request.args['q'])\n")
        self.assertEqual(self.ids(safe, ".py"), set())

    def test_php_js_ruby_go_java(self):
        self.assertIn(("shell-exec", True), self.ids("<?php system($_GET['c']); ?>\n", ".php"))
        self.assertIn(("file-include", True), self.ids("include($_REQUEST['page']);\n", ".php"))
        self.assertIn(("deserialise", True), self.ids("$o = unserialize($_COOKIE['s']);\n", ".php"))
        self.assertIn(("eval-input", True), self.ids("eval(req.body.code)\n", ".js"))
        self.assertIn(("shell-exec", True), self.ids("exec(`ls ${req.query.dir}`)\n", ".ts"))
        self.assertIn(("sql-format", True), self.ids("db.query(`SELECT * FROM t WHERE a=${req.params.a}`)\n", ".js"))
        self.assertIn(("tls-off", False), self.ids("{ rejectUnauthorized: false }\n", ".js"))
        self.assertIn(("shell-exec", True), self.ids('system("ls #{params[:d]}")\n', ".rb"))
        self.assertIn(("tls-off", False), self.ids("&tls.Config{InsecureSkipVerify: true}\n", ".go"))
        self.assertIn(("shell-exec", False), self.ids("Runtime.getRuntime().exec(cmd);\n", ".java"))

    def test_false_positives_seen_on_real_trees(self):
        # Each line was a match on real SDK and tool code on 2026-10-29.
        quiet = ["urllib.request.build_opener(HTTPCookieProcessor).open(url)\n",
                 "with open(self.args[0], 'rb') as f:\n",
                 '"""Fixer that changes input(...) into eval(input(...))."""\n',
                 "with urllib.request.urlopen(req, timeout=t) as resp, open(dest, 'wb') as out:\n",
                 "    \"    return eval(request.args['expr'])\\n\"\n",
                 "js_xhr.open(request.method, request.url, False)\n"]
        for line in quiet:
            with self.subTest(line=line):
                self.assertEqual(self.ids(line, ".py"), set())
        self.assertIn(("eval-input", True), self.ids("x = eval(self.request.GET['q'])\n", ".py"))
        self.assertIn(("file-include", True), self.ids("open(request.args['f'])\n", ".py"))

    def test_long_lines_and_unknown_languages_skipped(self):
        self.assertEqual(self.ids("eval(request.x)" + " " * 2000 + "\n", ".py"), set())
        self.assertEqual(self.ids("eval(request.x)\n", ".txt"), set())


# --- the whole audit ---------------------------------------------------------

class Audit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.srv = os.path.join(self.tmp, "srv")
        self.web = os.path.join(self.tmp, "www")
        self.state = os.path.join(self.tmp, "state")
        _write(self.srv, "shop/requirements.txt", "Django==4.2.1\n")
        _write(self.srv, "shop/app.py", "def view(request):\n    return eval(request.args['q'])\n")
        _write(self.srv, "shop/settings.py", f'GITHUB = "{GITHUB_TOKEN}"\n')
        _write(self.srv, "shop/tests/test_x.py", "eval(request.args['q'])\n")
        _write(self.srv, "shop/node_modules/x/index.js", "eval(req.body)\n")
        _write(self.srv, "blog/upload.php", "<?php echo 1; ?>\n", mode=0o666)
        _write(self.web, "html/.env", "DB_PASSWORD=x\n")
        _write(self.web, "html/.git/config", "[core]\n")
        self.index = _index("PyPI", {"django": [_entry("PYSEC-1", ranges=[("0", "4.2.2", None)],
                                                       severity="HIGH", aliases=["CVE-2023-31047"])]})

    def run_audit(self, **kw):
        kw.setdefault("roots", [self.srv])
        kw.setdefault("web_roots", [os.path.join(self.web, "html")])
        kw.setdefault("index", self.index)
        kw.setdefault("kev", set())
        kw.setdefault("which", lambda name: None)
        kw.setdefault("state_dir", self.state)
        kw.setdefault("now", 2000)
        kw.setdefault("extra_roots", [])
        return appcode.audit(**kw)

    def test_end_to_end(self):
        out = self.run_audit()
        titles = " | ".join(f"{f['severity']}:{f['title']}" for f in out)
        self.assertTrue(all(f["category"] == "appcode" for f in out))
        self.assertIn("medium:", titles)
        self.assertTrue(any("django" in f["detail"] and f["where"].endswith("shop") for f in out), titles)
        code = [f for f in out if "eval" in f["title"].lower()]
        self.assertEqual(len(code), 1, titles)
        self.assertEqual(code[0]["severity"], "medium")
        self.assertIn("app.py:2", code[0]["detail"])
        self.assertNotIn("test_x.py", code[0]["detail"])
        self.assertNotIn("node_modules", json.dumps(out))
        secret = [f for f in out if "credential" in f["title"].lower()]
        self.assertEqual(len(secret), 1, titles)
        self.assertEqual(secret[0]["severity"], "high")
        self.assertIn("settings.py:1", secret[0]["detail"])
        self.assertTrue(any(f["severity"] == "medium" and "writable" in f["title"] for f in out), titles)
        exposed = [f for f in out if "web root" in f["title"]]
        self.assertEqual(sorted(f["severity"] for f in exposed), ["high", "high"], titles)

    def test_titles_are_stable_across_runs(self):
        # A count in a title would make the same issue a new finding every run.
        out = self.run_audit()
        self.assertFalse([f["title"] for f in out if any(ch.isdigit() for ch in f["title"])])
        _write(self.srv, "shop/more.py", "eval(request.args['z'])\n")
        self.assertEqual(sorted(f["title"] for f in out), sorted(f["title"] for f in self.run_audit()))

    def test_no_code_text_or_secret_value_leaves_the_file(self):
        blob = json.dumps(self.run_audit())
        self.assertNotIn(GITHUB_TOKEN, blob)
        self.assertNotIn(GITHUB_TOKEN[4:20], blob)
        self.assertNotIn("request.args['q']", blob)
        self.assertNotIn("DB_PASSWORD", blob)

    def test_inventory_written_owner_only(self):
        self.run_audit()
        path = os.path.join(self.state, "inventory.json")
        doc = osvindex.load(path)
        self.assertEqual(doc["packages"][0]["name"], "django")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_scan_budget_exhaustion_is_stated_not_clean(self):
        out = self.run_audit(max_files=2)
        self.assertTrue(any(f["severity"] == "low" and "partly" in f["title"] for f in out))

    def test_symlinks_are_not_followed(self):
        os.symlink("/etc", os.path.join(self.srv, "shop", "etc-link"))
        self.assertNotIn("/etc/", json.dumps(self.run_audit()))

    def test_unreadable_roots_and_no_code_are_stated(self):
        out = appcode.audit(roots=[os.path.join(self.tmp, "absent")], web_roots=[], index=None,
                            kev=set(), which=lambda n: None, state_dir=self.state, now=1,
                            extra_roots=[])
        self.assertNotIn("ok", {f["severity"] for f in out})

    def test_own_install_is_not_scanned(self):
        inside = os.path.join(self.srv, "argus-self")
        _write(inside, "app.py", "eval(request.args['q'])\n")
        out = self.run_audit(exclude=[inside])
        self.assertNotIn("argus-self", json.dumps(out))


class Codebases(unittest.TestCase):
    """Every codebase on the server is found, listed and scanned, wherever it lives."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.srv = os.path.join(self.tmp, "srv")
        _write(self.srv, "shop/requirements.txt", "flask==2.0.0\n")
        _write(self.srv, "api/.git/HEAD", "ref: refs/heads/main\n")
        _write(self.srv, "api/main.go", "package main\n")
        _write(self.srv, "api/web/package.json", "{}\n")
        _write(self.srv, "api/web/src/app.js", "eval(req.body.code)\n")
        _write(self.srv, "notes/readme.txt", "hello\n")

    def test_codebases_are_detected_by_git_or_manifest(self):
        w = discover.walk([self.srv])
        self.assertEqual(sorted(os.path.relpath(c, self.srv) for c in w["codebases"]),
                         ["api", "api/web", "shop"])

    def test_findings_belong_to_the_nearest_codebase(self):
        w = discover.walk([self.srv])
        path = os.path.join(self.srv, "api/web/src/app.js")
        self.assertEqual(discover.project_of(path, [self.srv], w["codebases"]),
                         os.path.join(self.srv, "api/web"))
        loose = os.path.join(self.srv, "notes/readme.txt")
        self.assertEqual(discover.project_of(loose, [self.srv], w["codebases"]),
                         os.path.join(self.srv, "notes"))

    def test_service_units_name_their_code(self):
        app = os.path.join(self.tmp, "opt/app")
        os.makedirs(app)
        _write(app, "main.py", "print(1)\n")
        units = os.path.join(self.tmp, "units")
        _write(units, "shop.service", f"[Service]\nWorkingDirectory={self.srv}/shop\n"
                                      f"ExecStart=/usr/bin/python3 {app}/main.py --port 80\n")
        _write(units, "sys.service", "[Service]\nExecStart=-/usr/sbin/sshd -D\n")
        _write(units, "gone.service", "[Service]\nWorkingDirectory=/nonexistent/x\n")
        got = discover.service_paths([units])
        self.assertEqual(sorted(got), sorted([os.path.join(self.srv, "shop"), app]))

    def test_container_bind_mounts(self):
        mounts = [{"Mounts": [{"Type": "bind", "Source": self.srv},
                              {"Type": "volume", "Source": "/var/lib/docker/volumes/x"}]}]

        def run(argv, **kw):
            return (0, "abc\n") if argv[1] == "ps" else (0, json.dumps(mounts))
        paths, observed = discover.container_paths(which=lambda n: "/usr/bin/docker", run=run)
        self.assertEqual((paths, observed), ([self.srv], True))
        self.assertEqual(discover.container_paths(which=lambda n: None, run=run), ([], None))
        self.assertEqual(discover.container_paths(which=lambda n: "/usr/bin/docker",
                                                  run=lambda argv, **kw: (None, "")), ([], False))

    def test_audit_lists_codebases_and_scans_each(self):
        out = appcode.audit(roots=[self.srv], web_roots=[], index=None, kev=set(),
                            which=lambda n: None, state_dir=os.path.join(self.tmp, "st"), now=1,
                            extra_roots=[])
        inv = [f for f in out if "codebases" in f["title"]]
        self.assertEqual(len(inv), 1)
        for name in ("api", "api/web", "shop"):
            self.assertIn(os.path.join(self.srv, name), inv[0]["detail"])
        code = [f for f in out if "eval" in f["title"].lower()]
        self.assertEqual(code[0]["where"], os.path.join(self.srv, "api/web"))

    def test_extra_roots_from_services_are_scanned(self):
        other = os.path.join(self.tmp, "elsewhere/svc")
        _write(other, "app.py", "eval(request.args['q'])\n")
        out = appcode.audit(roots=[self.srv], web_roots=[], index=None, kev=set(),
                            which=lambda n: None, state_dir=os.path.join(self.tmp, "st"), now=1,
                            extra_roots=[other])
        self.assertTrue(any(f["where"] == other and "eval" in f["title"].lower() for f in out))


class ExternalTools(unittest.TestCase):
    def test_absent_tools_are_not_run(self):
        calls = []
        out = tools.run(["/srv/a"], which=lambda n: None, run=lambda *a, **k: calls.append(a),
                        semgrep_rules=None)
        self.assertEqual(calls, [])
        self.assertEqual(out, [])

    def test_bandit_results_folded_in(self):
        report = {"results": [
            {"filename": "/srv/a/x.py", "line_number": 3, "test_id": "B602",
             "issue_severity": "HIGH", "issue_confidence": "HIGH", "issue_text": "shell=True"},
            {"filename": "/srv/a/y.py", "line_number": 1, "test_id": "B101",
             "issue_severity": "LOW", "issue_confidence": "HIGH", "issue_text": "assert"}]}
        seen = []

        def run(argv, **kw):
            seen.append(argv)
            return 1, json.dumps(report)
        out = tools.run(["/srv/a"], which=lambda n: "/usr/bin/bandit" if n == "bandit" else None,
                        run=run, semgrep_rules=None)
        self.assertEqual(seen[0][0], "/usr/bin/bandit")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "medium")
        self.assertIn("x.py:3", out[0]["detail"])
        self.assertNotIn("y.py", out[0]["detail"])

    def test_semgrep_only_with_local_rules_and_metrics_off(self):
        seen = []

        def run(argv, **kw):
            seen.append(argv)
            return 0, json.dumps({"results": []})
        which = lambda n: "/usr/bin/semgrep" if n == "semgrep" else None  # noqa: E731
        tools.run(["/srv/a"], which=which, run=run, semgrep_rules=None)
        self.assertEqual(seen, [])
        rules_dir = tempfile.mkdtemp()
        tools.run(["/srv/a"], which=which, run=run, semgrep_rules=rules_dir)
        argv = seen[0]
        self.assertIn("--metrics=off", argv)
        self.assertEqual(argv[argv.index("--config") + 1], rules_dir)
        self.assertNotIn("auto", argv)

    def test_tool_failure_is_stated(self):
        out = tools.run(["/srv/a"], which=lambda n: "/usr/bin/bandit" if n == "bandit" else None,
                        run=lambda argv, **kw: (None, ""), semgrep_rules=None)
        self.assertEqual([f["severity"] for f in out], ["low"])


class Registration(unittest.TestCase):
    def test_jobs_declared_and_wired(self):
        from jarvis.service import jobs
        for name in ("appcode", "osv"):
            c = mechanisms.BY_NAME[name]
            self.assertEqual((c.domain, c.lane, c.governed), ("linux", "bulk", True), name)
            self.assertIsNone(c.area, name)
            self.assertTrue(c.unscored, name)
            self.assertIn(name, jobs.RUNNERS)

    def test_assurance_does_not_overclaim(self):
        from jarvis.core import assurance
        self.assertEqual(assurance.OBSERVATION_REQUIREMENTS["app_code_vulnerabilities"], ("appcode", "osv"))
        self.assertEqual(assurance.CAPABILITIES["app_code_vulnerabilities"][0], "unverified")

    def test_cli_scans_given_paths_without_touching_the_daemon_inventory(self):
        import argparse
        import contextlib

        from jarvis.cli.commands import server
        tmp = tempfile.mkdtemp()
        _write(tmp, "svc/app.py", "eval(request.args['q'])\n")
        state = os.path.join(tmp, "state")
        buf = io.StringIO()
        with mock.patch.object(osvindex, "ROOT", state), contextlib.redirect_stdout(buf):
            server.cmd_appcode(argparse.Namespace(paths=[os.path.join(tmp, "svc")], json=True), None)
        out = json.loads(buf.getvalue())
        self.assertTrue(any("eval" in f["title"].lower() for f in out))
        self.assertFalse(os.path.exists(os.path.join(state, "inventory.json")))
        p = argparse.ArgumentParser().add_subparsers()
        server.add_parser(p)
        self.assertIn("appcode", p.choices)

    def test_test_files_are_not_scanned(self):
        tmp = tempfile.mkdtemp()
        for name in ("src/api.test.ts", "src/x.spec.js", "pkg/test_views.py", "pkg/views_test.py",
                     "cmd/main_test.go", "src/FooTest.java", "src/__mocks__/m.js"):
            _write(tmp, name, "eval(request.args['q'])\n")
        keep = _write(tmp, "src/contest.py", "x = 1\n")
        self.assertEqual(discover.walk([tmp])["sources"], [keep])

    def test_hidden_tool_folders_are_not_codebases(self):
        tmp = tempfile.mkdtemp()
        _write(tmp, "home/u/.vscode-server/bin/x/package.json", "{}\n")
        _write(tmp, "home/u/.nvm/versions/node/lib/app.js", "eval(req.body)\n")
        _write(tmp, "home/u/site/package.json", "{}\n")
        w = discover.walk([os.path.join(tmp, "home")])
        self.assertEqual(w["codebases"], [os.path.join(tmp, "home/u/site")])
        self.assertEqual(w["sources"], [])
        # A hidden folder named as a root is still scanned.
        self.assertTrue(discover.walk([os.path.join(tmp, "home/u/.nvm")])["sources"])

    def test_bundled_interpreters_and_third_party_are_skipped(self):
        tmp = tempfile.mkdtemp()
        _write(tmp, "sdk/toolchain/lib/python3.11/http/cookiejar.py", "eval(request.args['q'])\n")
        _write(tmp, "sdk/lib/third_party/x/y.py", "eval(request.args['q'])\n")
        keep = _write(tmp, "app/main.py", "x = 1\n")
        self.assertEqual(discover.walk([tmp])["sources"], [keep])

    def test_module_caches_vendored_copies_and_sdks_are_not_codebases(self):
        # 2026-10-29 on this machine: 276 of 367 "codebases" were ~/go/pkg/mod entries.
        tmp = tempfile.mkdtemp()
        for rel in ("home/u/go/pkg/mod/google.golang.org/grpc@v1.83.2/go.mod",
                    "home/u/go/pkg/mod/cache/download/x/@v/list",
                    "home/u/proj/third/aws-sdk-go-v2@v1.47.1/go.mod",
                    "home/u/google-cloud-sdk/platform/gsutil/gslib/vendored/boto/setup.py",
                    "home/u/Android/Sdk/ndk/27.0/python-packages/fetchartifact/setup.py",
                    "home/u/app/lib/vendored/pkg/package.json"):
            _write(tmp, rel, "{}\n")
        mine = [_write(tmp, "home/u/proj/go.mod", "module x\n"), _write(tmp, "home/u/app/package.json", "{}\n"),
                _write(tmp, "home/u/sdk-tools/package.json", "{}\n"), _write(tmp, "home/u/pkg/mod-tool/go.mod", "m\n")]
        found = discover.walk([os.path.join(tmp, "home")])["codebases"]
        self.assertEqual(sorted(found), sorted(os.path.dirname(p) for p in mine))

    def test_discover_skips_dependency_trees(self):
        self.assertIn("node_modules", discover.SKIP_DIRS)
        self.assertIn(".git", discover.SKIP_DIRS)


if __name__ == "__main__":
    unittest.main()
