# !/usr/bin/env python3
import unittest
from datetime import datetime as dt

import sntp_message


class TestSNTPTimeStamps(unittest.TestCase):
    def test_dt_from_bytes(self):
        expected = dt(
            year=2018, month=2, day=21,
            hour=7, minute=50, second=32,
            microsecond=573172
        )
        actual = sntp_message._datetime_from_bytes(
            b"\xDE\x37\xA3\x48\x92\xBB\x68\x20")
        self.assertEqual(expected, actual)

    def test_dt_to_bytes(self):
        expected = b"\xDE\x37\xA3\x48\x92\xBB\x68\x00"
        actual = sntp_message.datetime_to_bytes(dt(
            year=2018, month=2, day=21,
            hour=7, minute=50, second=32,
            microsecond=573172
        ))
        self.assertEqual(expected, actual)
