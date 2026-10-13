import unittest

from shellsentry.core import AuditEngine, AuditRequest


class AuditEngineTests(unittest.TestCase):
    def test_local_scan_does_not_require_model_configuration(self):
        result = AuditEngine().audit(
            AuditRequest(filename="example.php", content="<?php echo 'hello';")
        )

        self.assertTrue(result.success)
        self.assertEqual(result.filename, "example.php")
        self.assertIsInstance(result.regex_scan, dict)

    def test_rejects_unsupported_binary_upload(self):
        result = AuditEngine().audit(
            AuditRequest(filename="program.exe", content=b"MZ\x00\x00")
        )

        self.assertFalse(result.success)
        self.assertTrue(result.errors)


    def test_rejects_pe_binary_renamed_as_text(self):
        result = AuditEngine().audit(
            AuditRequest(filename="notes.txt", content=b"MZ\x90\x00binary")
        )

        self.assertFalse(result.success)
        self.assertEqual(result.artifact["kind"], "binary")
        self.assertEqual(result.deterministic_verdict["verdict"], "unsupported")

    def test_xss_payload_is_not_reported_as_safe(self):
        result = AuditEngine().audit(
            AuditRequest(filename="payload.html", content="<img src=x onerror=alert(1)>")
        )

        self.assertTrue(result.success)
        self.assertIn(result.deterministic_verdict["verdict"], {"malicious", "suspicious"})
        self.assertTrue(result.findings)

    def test_no_static_hit_is_not_confirmed_benign(self):
        result = AuditEngine().audit(
            AuditRequest(filename="hello.py", content="print('hello')")
        )

        self.assertTrue(result.success)
        self.assertEqual(result.deterministic_verdict["verdict"], "no_indication")
if __name__ == "__main__":
    unittest.main()

