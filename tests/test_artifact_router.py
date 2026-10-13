import unittest

from shellsentry.core.artifact_router import route_bytes, route_text


class ArtifactRouterTests(unittest.TestCase):
    def test_rejects_renamed_pe_binary(self):
        profile = route_bytes("notes.txt", b"MZ" + b"\x00" * 100)
        self.assertFalse(profile.supported)
        self.assertTrue(profile.is_binary)

    def test_detects_javascript_from_unknown_extension(self):
        profile = route_text("payload.unknown", "document.location = '/'; fetch('/api')")
        self.assertTrue(profile.supported)
        self.assertEqual(profile.language, "javascript")

    def test_routes_unknown_readable_text_to_generic_analysis(self):
        profile = route_text("sample.custom", "alpha beta gamma")
        self.assertTrue(profile.supported)
        self.assertEqual(profile.language, "generic_text")


if __name__ == "__main__":
    unittest.main()

