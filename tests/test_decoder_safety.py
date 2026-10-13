import unittest
import zlib

from shellsentry.core.decoder import _try_inflate, MAX_INFLATE_OUTPUT


class InflateCapTests(unittest.TestCase):
    """解压炸弹必须被上限截断，不得膨胀拖垮进程（P1-5）。"""

    def test_normal_payload_round_trips(self):
        payload = b"eval($_POST['x']);" * 50
        self.assertEqual(_try_inflate(zlib.compress(payload)), payload)

    def test_gzip_and_raw_deflate_round_trip(self):
        payload = b"Runtime.getRuntime().exec(cmd);"
        gz = zlib.compress(payload, 9)
        # gzip：带 gzip 头（wbits=47 自动识别）
        gzip_blob = zlib.compressobj(9, zlib.DEFLATED, 31)
        gz2 = gzip_blob.compress(payload) + gzip_blob.flush()
        self.assertEqual(_try_inflate(gz), payload)
        self.assertEqual(_try_inflate(gz2), payload)

    def test_decompression_bomb_rejected(self):
        # 64 MB 全零 → 压缩后仅数十 KB，但膨胀远超 2 MB 上限
        bomb = zlib.compress(b"\x00" * (64 * 1024 * 1024))
        self.assertLess(len(bomb), MAX_INFLATE_OUTPUT)  # 确认它确实是"小输入"
        self.assertIsNone(_try_inflate(bomb))

    def test_non_zlib_data_returns_none(self):
        self.assertIsNone(_try_inflate(b"not-compressed-at-all"))

    def test_truncated_stream_rejected(self):
        # 截断/损坏的流应与旧版 zlib.decompress 一致地拒绝，不返回部分明文
        payload = b"eval($_POST['x']);" * 20
        truncated = zlib.compress(payload)[:-4]
        self.assertIsNone(_try_inflate(truncated))


if __name__ == "__main__":
    unittest.main()
