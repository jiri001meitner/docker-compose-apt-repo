from __future__ import annotations

import base64
import unittest
from datetime import timedelta

from repo_auth.auth import Decision, decide, normalize_path, parse_basic

from .helpers import NOW, OTHER_TOKEN, TOKEN, basic, entry, export, future


def run(
    exp: object,
    *,
    auth: str | None = None,
    uri: str | None = "/caddy/dists/any-version/Release",
    method: str | None = "GET",
) -> Decision:
    return decide(exp, method=method, uri=uri, authorization=auth, now=NOW)  # type: ignore[arg-type]


class ParseBasicTest(unittest.TestCase):
    def test_valid(self) -> None:
        self.assertEqual(parse_basic(basic("client-one", TOKEN)), ("client-one", TOKEN))

    def test_scheme_case_insensitive(self) -> None:
        self.assertIsNotNone(parse_basic(basic("client-one", TOKEN).replace("Basic", "bAsIc")))

    def test_rejects(self) -> None:
        cases = {
            "none": None,
            "empty": "",
            "bearer": "Bearer " + TOKEN,
            "no payload": "Basic ",
            "bad base64": "Basic !!!notbase64!!!",
            "base64 with junk": "Basic " + base64.b64encode(b"client-one:" + TOKEN.encode()).decode() + "*",
            "not utf8": "Basic " + base64.b64encode(b"client-one:\xff\xfe" + b"a" * 40).decode(),
            "no colon": "Basic " + base64.b64encode(b"client-one" + TOKEN.encode()).decode(),
            "uppercase login": basic("Client-One", TOKEN),
            "short login": basic("ab", TOKEN),
            "login with dot": basic("client.one", TOKEN),
            "short token": basic("client-one", "x" * 31),
            "token with space": basic("client-one", "x" * 20 + " " + "x" * 20),
            "token with colon": basic("client-one", "x" * 20 + ":" + "x" * 20),
            "long token": basic("client-one", "x" * 257),
            "huge header": "Basic " + "A" * 2000,
        }
        for name, header in cases.items():
            with self.subTest(name):
                self.assertIsNone(parse_basic(header))


class NormalizePathTest(unittest.TestCase):
    def test_accepts(self) -> None:
        self.assertEqual(normalize_path("/caddy/dists/x/Release"), "/caddy/dists/x/Release")
        self.assertEqual(normalize_path("/caddy/pool/"), "/caddy/pool/")
        self.assertEqual(normalize_path("/caddy/a%2Bb.deb?x=1#f"), "/caddy/a+b.deb")
        self.assertEqual(normalize_path("/"), "/")

    def test_rejects(self) -> None:
        for uri in [
            None,
            "",
            "caddy/x",
            "/caddy/../ppa/x",
            "/caddy/./x",
            "/caddy//x",
            "/caddy/%2e%2e/x",
            "/caddy/%2E%2E/x",
            "/caddy%2f..%2fppa/x",
            "/caddy/%252e%252e/x",
            "/caddy\\..\\x",
            "/caddy/%5c/x",
            "/caddy/%00/x",
            "/caddy/\x00",
            "/caddy/%0a",
            "/caddy/%ff%fe",
            "/..",
            "/" + "a" * 5000,
        ]:
            with self.subTest(uri=uri):
                self.assertIsNone(normalize_path(uri))


class DecideTest(unittest.TestCase):
    def test_not_loaded_is_closed(self) -> None:
        self.assertEqual(run(None, auth=basic("client-one", TOKEN)).status, 503)

    def test_ok(self) -> None:
        d = run(export(entry()), auth=basic("client-one", TOKEN))
        self.assertEqual((d.status, d.login, d.account), (200, "client-one", "acme"))

    def test_head_ok(self) -> None:
        self.assertEqual(run(export(entry()), auth=basic("client-one", TOKEN), method="HEAD").status, 200)

    def test_missing_credentials(self) -> None:
        self.assertEqual(run(export(entry())).status, 401)

    def test_unknown_login(self) -> None:
        self.assertEqual(run(export(entry()), auth=basic("client-two", TOKEN)).status, 401)

    def test_wrong_token(self) -> None:
        self.assertEqual(run(export(entry()), auth=basic("client-one", OTHER_TOKEN)).status, 401)

    def test_token_of_other_login(self) -> None:
        exp = export(entry(), entry("client-two", token=OTHER_TOKEN))
        self.assertEqual(run(exp, auth=basic("client-one", OTHER_TOKEN)).status, 401)

    def test_blocked(self) -> None:
        self.assertEqual(run(export(entry(blocked=True)), auth=basic("client-one", TOKEN)).status, 403)

    def test_expired_and_boundary(self) -> None:
        self.assertEqual(
            run(export(entry(valid_until=NOW - timedelta(seconds=1))), auth=basic("client-one", TOKEN)).status, 403
        )
        self.assertEqual(run(export(entry(valid_until=NOW)), auth=basic("client-one", TOKEN)).status, 403)
        self.assertEqual(run(export(entry(valid_until=future())), auth=basic("client-one", TOKEN)).status, 200)

    def test_method(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PROPFIND", "", None):
            with self.subTest(method=method):
                self.assertEqual(run(export(entry()), auth=basic("client-one", TOKEN), method=method).status, 403)

    def test_scope(self) -> None:
        exp = export(entry(scopes=("/caddy/", "/ppa/mozillateam/")))
        auth = basic("client-one", TOKEN)
        allowed = [
            "/caddy/",
            "/caddy",
            "/caddy/pool/main/c/caddy/caddy_2.11.9_amd64.deb",
            "/ppa/mozillateam/dists/resolute/InRelease",
        ]
        denied = [
            "/caddyx/dists/x",
            "/ppa/mozillateamx/dists",
            "/ppa/libreoffice/dists/resolute/Release",
            "/ppa/",
            "/",
            "/caddy/../ppa/libreoffice/x",
            "/caddy/%2e%2e/ppa/libreoffice/x",
        ]
        for uri in allowed:
            with self.subTest(uri=uri):
                self.assertEqual(run(exp, auth=auth, uri=uri).status, 200)
        for uri in denied:
            with self.subTest(uri=uri):
                self.assertEqual(run(exp, auth=auth, uri=uri).status, 403)

    def test_scope_everything(self) -> None:
        exp = export(entry(scopes=("/",)))
        self.assertEqual(run(exp, auth=basic("client-one", TOKEN), uri="/ppa/x/y").status, 200)
        self.assertEqual(run(exp, auth=basic("client-one", TOKEN), uri="/ppa/../etc/passwd").status, 403)

    def test_bad_credentials_before_other_checks(self) -> None:
        # No information leak: wrong token on a blocked/expired account is 401, not 403.
        exp = export(entry(blocked=True))
        self.assertEqual(run(exp, auth=basic("client-one", OTHER_TOKEN)).status, 401)


if __name__ == "__main__":
    unittest.main()
