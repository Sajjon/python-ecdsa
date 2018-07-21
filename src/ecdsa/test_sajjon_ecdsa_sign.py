from __future__ import with_statement, division


import sys, os
scriptPath = os.path.realpath(os.path.dirname(sys.argv[0]))
os.chdir(scriptPath)
sys.path.append(".")

import unittest
import os
import time
import shutil
import subprocess
import binascii#import hexlify, unhexlify
from hashlib import sha1, sha256, sha512

from six import b, print_, binary_type
from keys import SigningKey, VerifyingKey
from keys import BadSignatureError
# from . import util
from util import sigencode_der
# from util import sigencode_der, sigencode_strings
# from util import sigdecode_der, sigdecode_strings
from curves import Curve, UnknownCurveError
from curves import NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1
from ellipticcurve import Point
# from . import der
# from . import rfc6979
import rfc6979
import der
from ecdsa import Signature

def class_name(v):
    return type(v).__name__

def debug(value, variable_name):
    value_print_friendly = value
    if isinstance(value, bytes):
        value_print_friendly = 'hex=`{}`, int=`{}`'.format(str(binascii.hexlify(value), 'utf-8'), int.from_bytes(value, byteorder="big"))

    print('`{}`: `{}` = value=`{}`'.format(variable_name, class_name(value), value_print_friendly))


def test_signatures(secret, msg, expectedSignature):
    signing_key = SigningKey.from_secret_exponent(secret, SECP256k1)
    calculatedSignature = signing_key.sign_deterministic(msg, hashfunc=sha256, sigencode=sigencode_der)
    signHexStr = binascii.hexlify(calculatedSignature).decode("utf-8")
    assert signHexStr == expectedSignature, "Signature mismatch, expected {}, but got {}".format(expectedSignature, signHexStr)

def test_signatures_secp256k1(secret, msg, expectedSignature):
    test_signatures(int(secret, 16), msg.encode('utf-8'), expectedSignature)

# TEST VECTORS FROM: https://github.com/trezor/trezor-crypto/blob/957b8129bded180c8ac3106e61ff79a1a3df8893/tests/test_check.c#L1959-L1965
# But signature results from: https://github.com/oleganza/CoreBitcoin/blob/master/CoreBitcoinTestsOSX/BTCKeyTests.swift
def test_signatures_secp256k1_v0():
    test_signatures_secp256k1(
        'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721',
        'sample',
        '30440220432310e32cb80eb6503a26ce83cc165c783b870845fb8aad6d970889fcd7a6c80220530128b6b81c548874a6305d93ed071ca6e05074d85863d4056ce89b02bfab69'
    )
    print("TEST VECTOR 0 PASSED")

def test_signatures_secp256k1_v1():
    test_signatures_secp256k1(
        'cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50',
        'sample',
        '3045022100af340daf02cc15c8d5d08d7735dfe6b98a474ed373bdb5fbecf7571be52b384202205009fb27f37034a9b24b707b7c6b79ca23ddef9e25f7282e8a797efe53a8f124'
    )
    print("TEST VECTOR 1 PASSED")

def test_signatures_secp256k1_v2():
    test_signatures_secp256k1(
        '0000000000000000000000000000000000000000000000000000000000000001',
        'Satoshi Nakamoto',
        '3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5'
    )
    print("TEST VECTOR 2 PASSED")

def test_signatures_secp256k1_v3():
    test_signatures_secp256k1(
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
        'Satoshi Nakamoto',
        '3045022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d002206b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5'
    )
    print("TEST VECTOR 3 PASSED")

def test_signatures_secp256k1_v4():
    test_signatures_secp256k1(
        'f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181',
        'Alan Turing',
        '304402207063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c022058dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea'
    )
    print("TEST VECTOR 4 PASSED")

def test_signatures_secp256k1_v5():
    test_signatures_secp256k1(
        '0000000000000000000000000000000000000000000000000000000000000001',
        'All those moments will be lost in time, like tears in rain. Time to die...',
        '30450221008600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b0220547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21'
    )
    print("TEST VECTOR 5 PASSED")

def test_signatures_secp256k1_v6():
    test_signatures_secp256k1(
        'e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2',
        "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
        '3045022100b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b0220279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6'
    )
    print("TEST VECTOR 6 PASSED")

def test_signature_validity_curve256k1_vectors():
    test_signatures_secp256k1_v0() 
    test_signatures_secp256k1_v1() 
    test_signatures_secp256k1_v2() 
    test_signatures_secp256k1_v3() 
    test_signatures_secp256k1_v4() 
    test_signatures_secp256k1_v5() 
    test_signatures_secp256k1_v6() 

print("STARTIN TESTS")
# test_signature_validity_curve192_vectors()
test_signature_validity_curve256k1_vectors()
print("TESTING DONE")
