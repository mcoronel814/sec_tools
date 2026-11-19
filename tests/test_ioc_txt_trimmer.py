#!/usr/bin/env python3
"""Platform-name refusal for ioc_txt_trimmer.py."""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ioc_txt_trimmer import (
    DEFAULT_EXACT,
    DEFAULT_SHARED,
    load_exact_platform_names,
    load_shared_hosts,
    normalize_token,
    process_file,
)


SHARED = {"googleapis.com", "amazonaws.com", "t.me"}
EXACT = {"workers.dev", "cdn.jsdelivr.net", "github.io", "blob.core.windows.net"}


def run_file(text, mode="hybrid", shared=None, exact=None):
    shared = SHARED if shared is None else shared
    exact = EXACT if exact is None else exact
    with tempfile.TemporaryDirectory() as temp_dir:
        path = os.path.join(temp_dir, "ioc.txt")
        Path(path).write_text(text, encoding="utf-8")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = process_file(path, shared, mode, exact)
        written = Path(path).read_text(encoding="utf-8")
    return code, written, stdout.getvalue(), stderr.getvalue()


class PlatformRefusalTest(unittest.TestCase):
    def test_bare_shared_name_is_left_out(self):
        code, written, _out, err = run_file("googleapis.com\nmalware.example\n")
        self.assertEqual(code, 1)
        self.assertEqual(written, "malware.example\n")
        self.assertIn("refused platform name: googleapis.com", err)
        self.assertNotIn("googleapis.com\n", written)

    def test_defanged_shared_host_is_left_out(self):
        code, written, _out, err = run_file("storage[.]googleapis[.]com\n")
        self.assertEqual(code, 1)
        self.assertEqual(written, "")
        self.assertIn("refused platform name: storage.googleapis.com", err)

    def test_shared_host_with_a_port_is_left_out(self):
        _code, written, _out, err = run_file("storage.googleapis.com:443\n")
        self.assertEqual(written, "")
        self.assertIn("refused platform name: storage.googleapis.com", err)

    def test_shared_url_with_a_path_is_kept(self):
        code, written, _out, err = run_file(
            "https://storage.googleapis.com/bucket/malware.exe\n"
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            written,
            "https://storage.googleapis.com/bucket/malware.exe\n",
        )
        self.assertIn("kept URL (shared host storage.googleapis.com)", err)

    def test_shared_url_with_no_path_is_left_out(self):
        _code, written, _out, err = run_file("https://storage.googleapis.com/\n")
        self.assertEqual(written, "")
        self.assertIn("refused platform name: storage.googleapis.com", err)

    def test_exact_cdn_url_is_kept_and_bare_name_is_refused(self):
        code, written, _out, err = run_file(
            "https://cdn.jsdelivr.net/npm/left-pad\ncdn.jsdelivr.net\n"
        )
        self.assertEqual(code, 1)
        self.assertEqual(written, "https://cdn.jsdelivr.net/npm/left-pad\n")
        self.assertIn("refused platform name: cdn.jsdelivr.net", err)
        self.assertIn("kept URL (shared host cdn.jsdelivr.net)", err)

    def test_worker_suffix_is_refused_and_tenant_is_written(self):
        code, written, _out, err = run_file(
            "workers.dev\n"
            "https://evil-tenant.workers.dev/api/a\n"
            "https://evil-tenant.workers.dev/api/b\n"
        )
        self.assertEqual(code, 1)
        self.assertEqual(written, "evil-tenant.workers.dev\n")
        self.assertIn("refused platform name: workers.dev", err)

    def test_azure_blob_account_collapses_and_the_service_host_is_kept(self):
        code, written, _out, _err = run_file(
            "https://evilacct.blob.core.windows.net/c/x\n"
            "https://blob.core.windows.net/acct/blob\n"
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            written,
            "evilacct.blob.core.windows.net\n"
            "https://blob.core.windows.net/acct/blob\n",
        )

    def test_bare_s3_bucket_under_amazonaws_is_left_out(self):
        _code, written, _out, err = run_file(
            "cvbhnjkjhgsdf.s3.us-east-2.amazonaws.com\n"
            "https://cvbhnjkjhgsdf.s3.us-east-2.amazonaws.com/obj/a\n"
        )
        self.assertIn("refused platform name: cvbhnjkjhgsdf.s3.us-east-2.amazonaws.com", err)
        self.assertEqual(
            written,
            "https://cvbhnjkjhgsdf.s3.us-east-2.amazonaws.com/obj/a\n",
        )

    def test_hosts_only_still_protects_platform_names(self):
        code, written, _out, err = run_file(
            "https://storage.googleapis.com/bucket/a.exe\n"
            "googleapis.com\n"
            "https://evil.example/a\n",
            mode="hosts-only",
        )
        self.assertEqual(code, 1)
        self.assertEqual(
            written,
            "https://storage.googleapis.com/bucket/a.exe\n"
            "evil.example\n",
        )
        self.assertIn("refused platform name: googleapis.com", err)

    def test_keep_urls_still_refuses_a_bare_platform_name(self):
        _code, written, _out, err = run_file(
            "https://evil.example/a\ngoogleapis.com\n",
            mode="keep-urls",
        )
        self.assertEqual(written, "https://evil.example/a\n")
        self.assertIn("refused platform name: googleapis.com", err)

    def test_ordinary_malware_url_still_collapses(self):
        code, written, _out, _err = run_file(
            "https://evil-cdn.bad-example.com/payload.exe\n"
        )
        self.assertEqual(code, 0)
        self.assertEqual(written, "evil-cdn.bad-example.com\n")

    def test_shipped_lists_cover_the_known_outage_names(self):
        shared = load_shared_hosts(None)
        exact = load_exact_platform_names()
        self.assertTrue(DEFAULT_SHARED.is_file())
        self.assertTrue(DEFAULT_EXACT.is_file())
        for name in ("googleapis.com", "amazonaws.com", "microsoftonline.com"):
            self.assertIn(name, shared)
        for name in (
            "cdn.jsdelivr.net",
            "unpkg.com",
            "cdnjs.cloudflare.com",
            "blob.core.windows.net",
            "workers.dev",
            "github.io",
            "netlify.app",
        ):
            self.assertIn(name, exact)
        value, note = normalize_token("googleapis.com", shared, "hybrid", exact)
        self.assertEqual(value, "")
        self.assertIn("refused platform name: googleapis.com", note)


if __name__ == "__main__":
    unittest.main()
