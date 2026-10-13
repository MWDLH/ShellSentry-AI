import unittest

from shellsentry.cli import build_parser


class CliTests(unittest.TestCase):
    def test_serve_defaults_to_stable_port_and_opens_browser(self):
        args = build_parser().parse_args(["serve"])
        self.assertEqual(args.port, 8765)
        self.assertFalse(args.no_browser)

    def test_serve_accepts_port_and_no_browser(self):
        args = build_parser().parse_args(["serve", "--port", "0", "--no-browser"])
        self.assertEqual(args.port, 0)
        self.assertTrue(args.no_browser)

    def test_serve_rejects_invalid_port(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["serve", "--port", "70000"])


if __name__ == "__main__":
    unittest.main()
