from mock import Mock

from cellar.secret import Cellar, default_logger

from .base import CellarTests


class CellarInitTests(CellarTests):
    def test_short_key(self):
        "a shorter key than allowed"
        self.assertRaises(ValueError, Cellar, 'short key')

    def test_init(self):
        "init values on Ceellar"
        self.assertEqual(self.cellar.attr, 'value')
        self.assertIsInstance(self.cellar.logger, Mock)
        self.assertEqual(self.cellar.verbosity, 3)
