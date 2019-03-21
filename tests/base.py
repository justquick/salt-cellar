from unittest import TestCase
from mock import MagicMock
import os

from cellar.secret import Cellar


class CellarTests(TestCase):
    mocked_random = MagicMock(return_value='randomstring' * 2)
    plaintext = 'abcd'
    ciphertext = 'randomstringrandomstring5\x02\x07RYP\x8f\xf6\x1c\xff\xd0\xcf\x91\xa3]\xb5\x90\x98\xfb\x8d'
    ciphertext32 = 'OJQW4ZDPNVZXI4TJNZTXEYLOMRXW243UOJUW4ZZVAIDVEWKQR73BZ76QZ6I2GXNVSCMPXDI='
    cipherfoo = 'randomstringrandomstringOEl\x07\xc6\x07[\xea}\x0e}\x02\x10\xce\xc4\xd8\x97\x95\xf7\xe3'
    level32 = 'OJQW4ZDPNVZXI4TJNZTXEYLOMRXW243UOJUW4Z2VV4B744Q27VNJ75JWZH4P6D7B32JPPBEGOS2HBQLUM752AJRU4YPP6WVAUH2V336TKIT57E2VI7QDNGJLRVE367DUQS2GPZI3DVEA7ESXTB3T7GYWAGOYZFQ='

    def setUp(self):
        super(CellarTests, self).setUp()
        self.cellar = Cellar('k' * 32, attr='value', logger=MagicMock())

    def test_path(self, *args):
        testdir = os.path.abspath(os.path.dirname(__file__))
        return os.path.join(testdir, 'data', *args)