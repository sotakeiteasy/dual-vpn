"""Рабочий конфиг с сайта: запрос, разбор ответа, отказы — без сети."""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib", "scripts"))

import corpconf  # noqa: E402

CONF = "[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n[Peer]\n"


def done(body, rc=0, stderr=b""):
    out = json.dumps(body).encode() if body is not None else b""
    return mock.Mock(returncode=rc, stdout=out, stderr=stderr)


class PostTests(unittest.TestCase):
    def post(self, reply, fn, *args):
        with mock.patch.object(corpconf.subprocess, "run", return_value=reply) as run:
            got = fn(*args)
        return got, run.call_args

    def test_request_body_goes_through_stdin(self):
        got, call = self.post(done({"success": True, "expires_in_minutes": 10}),
                              corpconf.request, " Ivanov@Media-Effect.ru ", "mac")
        self.assertEqual(got, 10)
        argv = call.args[0]
        self.assertEqual(argv[-1], corpconf.SITE + "/api/request-config")
        self.assertIn("--fail-with-body", argv)
        # Почта — только в теле: аргументы видны в списке процессов.
        self.assertFalse(any("ivanov" in a.lower() for a in argv))
        self.assertEqual(json.loads(call.kwargs["input"]),
                         {"email": "ivanov@media-effect.ru", "client_name": "mac"})

    def test_site_refusal_shows_its_message(self):
        # --fail-with-body: при 4xx curl выходит с 22, но тело с причиной отдаёт.
        reply = done({"success": False, "message": "Неверный код"}, rc=22)
        with mock.patch.object(corpconf.subprocess, "run", return_value=reply):
            with self.assertRaisesRegex(corpconf.CorpConfError, "Неверный код"):
                corpconf.verify("ivanov@media-effect.ru", "123456")

    def test_network_error_without_body(self):
        reply = done(None, rc=6, stderr=b"curl: (6) Could not resolve host")
        with mock.patch.object(corpconf.subprocess, "run", return_value=reply):
            with self.assertRaisesRegex(corpconf.CorpConfError, "resolve host"):
                corpconf.request("ivanov@media-effect.ru", "mac")

    def test_verify_returns_config(self):
        got, call = self.post(done({"success": True, "config": CONF}),
                              corpconf.verify, "ivanov@media-effect.ru", " 123456 ")
        self.assertEqual(got, CONF)
        self.assertEqual(json.loads(call.kwargs["input"])["code"], "123456")


class RefusalTests(unittest.TestCase):
    def test_config_without_private_key(self):
        with self.assertRaises(corpconf.CorpConfError):
            corpconf.parse_config({"success": True, "config": "[Interface]\nAddress = x\n"})

    def test_foreign_email_never_reaches_network(self):
        with mock.patch.object(corpconf.subprocess, "run") as run:
            for bad in ("ivanov@gmail.com", "ivanov@media-effect.ru.evil.com",
                        "@media-effect.ru", "../x@media-effect.ru"):
                with self.assertRaises(corpconf.CorpConfError, msg=bad):
                    corpconf.request(bad, "mac")
        run.assert_not_called()

    def test_code_must_be_six_digits(self):
        with mock.patch.object(corpconf.subprocess, "run") as run:
            with self.assertRaises(corpconf.CorpConfError):
                corpconf.verify("ivanov@media-effect.ru", "12345a")
        run.assert_not_called()

    def test_file_name_matches_site(self):
        self.assertEqual(corpconf.file_name("Ivan.Ov@media-effect.ru"), "wg0-ivan.ov.conf")


if __name__ == "__main__":
    unittest.main()
