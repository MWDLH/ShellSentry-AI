import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shellsentry.paths import config_file, data_dir, history_dir


class StoragePathTests(unittest.TestCase):
    def test_explicit_data_directory_keeps_runtime_data_outside_package(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"SHELLSENTRY_DATA_DIR": temp_dir}):
                expected = Path(temp_dir).resolve()
                self.assertEqual(data_dir(), expected)
                self.assertEqual(config_file(), expected / "config.json")
                self.assertEqual(history_dir(), expected / "history")


if __name__ == "__main__":
    unittest.main()

