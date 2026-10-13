import socket
import unittest

from shellsentry.web.app import _select_port


class WebStartupTests(unittest.TestCase):
    def test_random_port_request_is_preserved(self):
        self.assertEqual(_select_port(0), 0)

    def test_occupied_preferred_port_falls_back_to_random(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        try:
            occupied_port = listener.getsockname()[1]
            self.assertEqual(_select_port(occupied_port), 0)
        finally:
            listener.close()


if __name__ == "__main__":
    unittest.main()
