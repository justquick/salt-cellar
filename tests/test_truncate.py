from unittest import TestCase

from cellar.secret import truncate


class TruncateTests(TestCase):
    def test_truncate_short(self):
        "make sure 'a' is 'a'"
        self.assertEqual(truncate('a'), 'a')

    def test_truncate_long(self):
        "make sure it's truncated and has ..."
        self.assertEqual(truncate('the quick brown fox jumped over the lazy dog'), 'the quick ...e lazy dog')
