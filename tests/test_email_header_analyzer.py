#!/usr/bin/env python3
"""Action-level checks for email_header_spoofing_analyzer.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from email_header_spoofing_analyzer import (
    OrgWatch,
    analyze,
    parse_header_bytes,
    recommended_action,
)


def run(raw: str, org: OrgWatch | None = None):
    data = raw.encode()
    headers, text = parse_header_bytes(data)
    result = analyze(headers, text, org if org is not None else OrgWatch())
    return result, recommended_action(result)


def severities(result, category=None):
    return [
        (f.severity, f.category, f.message)
        for f in result.findings
        if category is None or f.category == category
    ]


class ActionTests(unittest.TestCase):
    def test_esp_return_path_with_dmarc_pass_is_not_a_block(self):
        result, action = run(
            """From: Payroll <payroll@partner.example>
Return-Path: <bounce@mail.esp-example.net>
Authentication-Results: mx.example; spf=pass smtp.mailfrom=mail.esp-example.net;
 dkim=pass header.d=partner.example; dmarc=pass (p=reject) header.from=partner.example
DKIM-Signature: v=1; d=partner.example; s=s1
Received: from mail.esp-example.net (mail.esp-example.net [203.0.113.10]) by mx.example
Subject: Invoice attached
To: analyst@corp.example
"""
        )
        self.assertEqual(action["action"], "MONITOR")
        self.assertTrue(any("Often an ESP or mailing list" in msg for _, _, msg in severities(result, "identity")))

    def test_return_path_mismatch_without_dmarc_still_blocks(self):
        _result, action = run(
            """From: Payroll <payroll@partner.example>
Return-Path: <bounce@mail.esp-example.net>
Received: from mail.esp-example.net ([203.0.113.10]) by mx.example
Subject: Invoice
To: analyst@corp.example
"""
        )
        self.assertEqual(action["action"], "BLOCK")

    def test_mailing_list_return_path_is_not_a_block(self):
        result, action = run(
            """From: List <list@partner.example>
Return-Path: <bounce@lists.example.net>
List-Unsubscribe: <mailto:unsub@lists.example.net>
Received: from lists.example.net ([203.0.113.11]) by mx.example
Subject: Digest
To: analyst@corp.example
"""
        )
        self.assertNotEqual(action["action"], "BLOCK")
        self.assertTrue(any(sev == "LOW" and "mailing-list" in msg for sev, _, msg in severities(result, "identity")))

    def test_extra_dkim_fail_does_not_block_an_aligned_pass(self):
        result, action = run(
            """From: CEO <ceo@corp.example>
Return-Path: <ceo@corp.example>
Authentication-Results: mx.example; spf=pass smtp.mailfrom=corp.example;
 dkim=pass header.d=corp.example; dkim=fail header.d=lists.example;
 dmarc=pass (p=reject) header.from=corp.example
DKIM-Signature: v=1; d=corp.example; s=s1
DKIM-Signature: v=1; d=lists.example; s=s1
Subject: Notes
To: analyst@corp.example
Received: from mail.corp.example ([203.0.113.21]) by mx.example
"""
        )
        self.assertEqual(action["action"], "MONITOR")
        self.assertFalse(any(sev == "HIGH" and cat == "dkim" for sev, cat, _ in severities(result)))

    def test_lone_dkim_fail_still_blocks(self):
        _result, action = run(
            """From: CEO <ceo@corp.example>
Return-Path: <ceo@corp.example>
Authentication-Results: mx.example; dkim=fail header.d=corp.example
Subject: Notes
To: analyst@corp.example
Received: from somewhere ([203.0.113.22]) by mx.example
"""
        )
        self.assertEqual(action["action"], "BLOCK")

    def test_reply_to_with_dmarc_pass_is_investigate_not_block(self):
        _result, action = run(
            """From: IT Helpdesk <it@corp.example>
Return-Path: <it@corp.example>
Reply-To: attacker@evil.example
Authentication-Results: mx.example; spf=pass smtp.mailfrom=corp.example;
 dkim=pass header.d=corp.example; dmarc=pass (p=reject) header.from=corp.example
Subject: Password reset
To: analyst@corp.example
Received: from mail.corp.example ([203.0.113.20]) by mx.example
"""
        )
        self.assertEqual(action["action"], "INVESTIGATE")

    def test_nonspam_sender_group_is_not_risk(self):
        result, action = run(
            """From: Good <good@vendor.example>
To: analyst@corp.example
Subject: Weekly update
X-IronPort-SenderGroup: NONSPAM
Authentication-Results: mx.example; spf=pass smtp.mailfrom=vendor.example;
 dkim=pass header.d=vendor.example; dmarc=pass header.from=vendor.example
Received: from mail.vendor.example ([203.0.113.50]) by mx.example
"""
        )
        self.assertEqual(action["action"], "MONITOR")
        self.assertFalse(any(sev == "HIGH" for sev, _, _ in severities(result, "gateway")))

    def test_suspectlist_sender_group_is_high(self):
        _result, action = run(
            """From: Good <good@vendor.example>
To: analyst@corp.example
Subject: Weekly update
X-IronPort-SenderGroup: SUSPECTLIST
Authentication-Results: mx.example; spf=pass smtp.mailfrom=vendor.example;
 dkim=pass header.d=vendor.example; dmarc=pass header.from=vendor.example
Received: from mail.vendor.example ([203.0.113.50]) by mx.example
"""
        )
        self.assertEqual(action["action"], "QUARANTINE")

    def test_ordinary_subject_words_are_not_a_gateway_tag(self):
        _result, action = run(
            """From: Vendor <v@vendor.example>
To: analyst@corp.example
Subject: External meeting notes and a precaution
Authentication-Results: mx.example; spf=pass smtp.mailfrom=vendor.example;
 dkim=pass header.d=vendor.example; dmarc=pass (p=none) header.from=vendor.example
Received: from mail.vendor.example ([203.0.113.40]) by mx.example
"""
        )
        self.assertEqual(action["action"], "MONITOR")

    def test_suspected_spam_subject_is_medium(self):
        _result, action = run(
            """From: Vendor <v@vendor.example>
To: analyst@corp.example
Subject: [SUSPECTED SPAM] hello
Authentication-Results: mx.example; spf=pass smtp.mailfrom=vendor.example;
 dkim=pass header.d=vendor.example; dmarc=pass header.from=vendor.example
Received: from mail.vendor.example ([203.0.113.40]) by mx.example
"""
        )
        self.assertEqual(action["action"], "INVESTIGATE")

    def test_microsoft_dmarc_action_quarantine_is_a_strong_fail(self):
        result, action = run(
            """From: Someone <someone@vendor.example>
Return-Path: <someone@vendor.example>
Authentication-Results: mx.example; spf=pass smtp.mailfrom=vendor.example;
 dkim=pass header.d=vendor.example; dmarc=fail action=quarantine header.from=vendor.example
Subject: Hello
To: analyst@corp.example
Received: from mail.vendor.example ([203.0.113.30]) by mx.example
"""
        )
        self.assertEqual(action["action"], "BLOCK")
        messages = [msg for sev, _, msg in severities(result, "dmarc") if sev == "HIGH"]
        self.assertTrue(messages)
        self.assertIn("quarantine", messages[0].lower())
        self.assertNotIn("monitoring only", messages[0].lower())

    def test_forefront_phish_is_not_monitor(self):
        result, action = run(
            """From: a@b.example
To: c@corp.example
Subject: hi
Return-Path: <a@b.example>
X-Forefront-Antispam-Report: CIP:203.0.113.70;SCL:9;SFV:SPM;CAT:PHSH;DIR:INB;
Authentication-Results: mx.example; spf=pass smtp.mailfrom=b.example; dkim=pass header.d=b.example; dmarc=pass header.from=b.example
Received: from x ([203.0.113.70]) by mx.example
"""
        )
        self.assertEqual(action["action"], "QUARANTINE")
        self.assertTrue(any("PHSH" in msg and "SCL=9" in msg for _, _, msg in severities(result, "gateway")))

    def test_our_domain_with_spf_fail_is_impersonation(self):
        org = OrgWatch(domains={"corp.example"})
        result, action = run(
            """From: Boss <boss@corp.example>
Return-Path: <boss@corp.example>
Authentication-Results: mx.example; spf=fail smtp.mailfrom=corp.example
Subject: Wire transfer
To: analyst@corp.example
Received: from evil ([203.0.113.80]) by mx.example
""",
            org,
        )
        self.assertEqual(action["action"], "BLOCK")
        self.assertTrue(any("treat as impersonation" in msg for _, _, msg in severities(result, "identity")))

    def test_our_domain_with_dmarc_pass_is_not_impersonation(self):
        org = OrgWatch(domains={"corp.example"})
        result, _action = run(
            """From: Boss <boss@corp.example>
Return-Path: <boss@corp.example>
Authentication-Results: mx.example; spf=pass smtp.mailfrom=corp.example;
 dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example
Subject: Notes
To: analyst@corp.example
Received: from mail.corp.example ([203.0.113.81]) by mx.example
""",
            org,
        )
        self.assertFalse(any("impersonation" in msg for _, _, msg in severities(result, "identity")))

    def test_lookalike_and_watched_display_name(self):
        org = OrgWatch(domains={"example.gov"}, names=["IT Helpdesk"])
        look, action = run(
            """From: Records <records@example.com>
Return-Path: <records@example.com>
Authentication-Results: mx; spf=pass smtp.mailfrom=example.com;
 dkim=pass header.d=example.com; dmarc=pass header.from=example.com
Subject: Tax bill
To: analyst@corp.example
Received: from mail.example ([203.0.113.90]) by mx
""",
            org,
        )
        self.assertEqual(action["action"], "BLOCK")
        self.assertTrue(any("looks like our domain" in msg for _, _, msg in severities(look, "identity")))

        named, named_action = run(
            """From: "IT Helpdesk" <user@gmail.com>
Return-Path: <user@gmail.com>
Authentication-Results: mx; spf=pass smtp.mailfrom=gmail.com;
 dkim=pass header.d=gmail.com; dmarc=pass (p=reject) header.from=gmail.com
Subject: Password reset
To: analyst@corp.example
Received: from mail.gmail.com ([203.0.113.91]) by mx
""",
            org,
        )
        self.assertEqual(named_action["action"], "BLOCK")
        self.assertTrue(any("Watched display name" in msg for _, _, msg in severities(named, "identity")))

    def test_srs_forwarder_is_named_and_the_authenticated_from_is_spared(self):
        org = OrgWatch(domains={"corp.example"})
        result, action = run(
            """From: Books <books@notification.vendor.example>
Return-Path: <bounces+SRS=E7nYK=JI@forwarder.example>
To: info-006@outside.example
X-MS-Exchange-Processed-By-BccFoldering: 15.02.2562.056
X-IronPort-AV: E=Sophos;i="6.27,220,1787025600"; d="pdf'?scan'208";a="41005748"
X-Forefront-Antispam-Report: CIP:203.0.113.51;SCL:5;SFV:SPM;CAT:OSPM;DIR:OUT;
X-MS-Exchange-Organization-SCL: 0
Authentication-Results: mx.example; spf=pass smtp.mailfrom=bounces+SRS=E7nYK=JI@forwarder.example;
 dkim=pass header.d=notification.vendor.example; dkim=pass header.d=tenant.onmicrosoft.com;
 dmarc=pass (p=reject dis=none) header.from=notification.vendor.example
DKIM-Signature: v=1; d=notification.vendor.example; s=s1
DKIM-Signature: v=1; d=secureserver.net; s=s2
DKIM-Signature: v=1; d=tenant.onmicrosoft.com; s=selector1
Subject: Thank you
Received: from send.example ([203.0.113.10]) by mx.example
""",
            org,
        )
        self.assertEqual(action["action"], "QUARANTINE")
        self.assertTrue(any("rewritten with SRS" in msg and "forwarder.example" in msg for _, _, msg in severities(result)))
        self.assertTrue(any("SCL=5" in msg and "Exchange SCL=0 disagrees" in msg for _, _, msg in severities(result, "gateway")))
        self.assertTrue(any("pdf" in msg for _, _, msg in severities(result, "content")))
        text = "\n".join(action["lines"])
        self.assertIn("forwarder.example", text)
        self.assertIn("info-006@outside.example", text)
        self.assertIn("outside.example", text)
        self.assertIn("tenant.onmicrosoft.com", text)
        self.assertIn("Do not block:", text)
        self.assertIn("books@notification.vendor.example", text)
        self.assertNotIn("secureserver.net —", text)
        self.assertNotIn("Often an ESP", "\n".join(msg for _, _, msg in severities(result)))


if __name__ == "__main__":
    unittest.main()
