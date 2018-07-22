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
from util import sigencode_der, sigdecode_der
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


def test_deterministic_signatures(curve, secret, msg, expectedK, expectedSignature=None, expectedSignR=None, expectedSignS=None, hashfunc=sha256, ensure_low_s_according_to_bip62=True):
    msg = msg.encode('utf-8')
    secret = int(secret, 16)
    signing_key = SigningKey.from_secret_exponent(secret, curve)
    (k, calculatedSignature) = signing_key.sign_deterministic(msg, hashfunc=hashfunc, sigencode=sigencode_der, ensure_low_s_according_to_bip62=ensure_low_s_according_to_bip62)
    hexedK = format(k, 'x')
    assert hexedK == expectedK, "Deterministic K mismatch, expected {}, but got {}".format(expectedK, hexedK)
    r, s = sigdecode_der(calculatedSignature, curve.order)

    if expectedSignature != None:
        signHexStr = binascii.hexlify(calculatedSignature).decode("utf-8")
        assert signHexStr == expectedSignature, "Signature mismatch, expected {}, but got {}, and r={} ('{}'), s={} ('{}')".format(expectedSignature, signHexStr, r, hex(r), s, hex(s))
    else:
        assert r == expectedSignR
        assert s == expectedSignS, "Signature S mismatch, expected {}, but got {}".format(format(expectedSignS, 'x'), format(s, 'x'))


def test_signatures_secp256k1(secret, msg, expectedK, expectedSignature, ensure_low_s_according_to_bip62=True):
    test_deterministic_signatures(SECP256k1, secret, msg, expectedK, expectedSignature, ensure_low_s_according_to_bip62=ensure_low_s_according_to_bip62)

def test_signatures_secp256r1(hashfunc, msg, k, r, s, ensure_low_s_according_to_bip62=False):
    test_deterministic_signatures(
        NIST256p,
        'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721',
        msg,
        expectedK=k,
        expectedSignature=None,
        expectedSignR=r,
        expectedSignS=s,
        hashfunc=hashfunc,
        ensure_low_s_according_to_bip62=ensure_low_s_according_to_bip62
    )

# TEST VECTORS FROM: https://github.com/trezor/trezor-crypto/blob/957b8129bded180c8ac3106e61ff79a1a3df8893/tests/test_check.c#L1959-L1965
# But signature results from: https://github.com/oleganza/CoreBitcoin/blob/master/CoreBitcoinTestsOSX/BTCKeyTests.swift
def test_signatures_secp256k1_v0():
    test_signatures_secp256k1(
        'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
        "sample",
        'a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60',
        '30440220432310e32cb80eb6503a26ce83cc165c783b870845fb8aad6d970889fcd7a6c80220530128b6b81c548874a6305d93ed071ca6e05074d85863d4056ce89b02bfab69'
    )
    print("TEST VECTOR 0 PASSED")

def test_signatures_secp256k1_v1():
    test_signatures_secp256k1(
        'cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50',
        "sample",
        '2df40ca70e639d89528a6b670d9d48d9165fdc0febc0974056bdce192b8e16a3',
        '3045022100af340daf02cc15c8d5d08d7735dfe6b98a474ed373bdb5fbecf7571be52b384202205009fb27f37034a9b24b707b7c6b79ca23ddef9e25f7282e8a797efe53a8f124'
    )
    print("TEST VECTOR 1 PASSED")

      # https://bitcoin.stackexchange.com/questions/50980/test-r-s-values-for-signature-generation
      # https://bitcointalk.org/index.php?topic=285142.msg3299061#msg3299061
def test_signatures_secp256k1_v2():
    print("STARTED TEST VECTOR 2")
    test_signatures_secp256k1(
        '0000000000000000000000000000000000000000000000000000000000000001',
        "Satoshi Nakamoto",
        '8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15',
        '3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5',
    )
    print("TEST VECTOR 2 PASSED")

def test_signatures_secp256k1_v3():
    print("STARTED TEST VECTOR 3")
    test_signatures_secp256k1(
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
        "Satoshi Nakamoto",
        '33a19b60e25fb6f4435af53a3d42d493644827367e6453928554f43e49aa6f90',
        '3045022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d002206b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5',
    )
    print("TEST VECTOR 3 PASSED")

def test_signatures_secp256k1_v4():
    print("STARTED TEST VECTOR 4")
    test_signatures_secp256k1(
        'f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181',
        "Alan Turing",
        '525a82b70e67874398067543fd84c83d30c175fdc45fdeee082fe13b1d7cfdf1',
        '304402207063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c022058dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea'
    )
    print("TEST VECTOR 4 PASSED")

def test_signatures_secp256k1_v5():
    print("STARTED TEST VECTOR 5")
    test_signatures_secp256k1(
        '0000000000000000000000000000000000000000000000000000000000000001',
        "All those moments will be lost in time, like tears in rain. Time to die...",
        '38aa22d72376b4dbc472e06c3ba403ee0a394da63fc58d88686c611aba98d6b3',
        '30450221008600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b0220547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21'
    )
    print("TEST VECTOR 5 PASSED")

def test_signatures_secp256k1_v6():
    print("STARTED TEST VECTOR 6")
    test_signatures_secp256k1(
        'e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2',
        "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
        '1f4b84c23a86a221d233f2521be018d9318639d5b8bbd6374a8a59232d16ad3d',
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

def test_signatures_secp256r1_sha1_v1():
    print("STARTED TEST r1 sha1 VECTOR 1")
    test_signatures_secp256r1(
        hashfunc=sha1,
        msg="sample",
        k='882905f1227fd620fbf2abf21244f0ba83d0dc3a9103dbbee43a1fb858109db4',
        r=0x61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32,
        s=0x6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB
    )
    print("TEST r1 sha1 VECTOR 1 PASSED")

def test_signatures_secp256r1_sha1_v2():
    print("STARTED TEST r1 sha1 VECTOR 2")
    test_signatures_secp256r1(
        hashfunc=sha1,
        msg="test",
        k='8c9520267c55d6b980df741e56b4adee114d84fbfa2e62137954164028632a2e',
        r=0x0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89,
        s=0x01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1
    )
    print("TEST r1 sha1 VECTOR 2 PASSED")

def test_signatures_secp256r1_sha256_v1():
    print("STARTED TEST r1 sha256 VECTOR 1")
    test_signatures_secp256r1(
        hashfunc=sha256,
        msg="sample",
        k='a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60',
        r=0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
        s=0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
    )
    print("TEST r1 sha256 VECTOR 1 PASSED")

def test_signatures_secp256r1_sha256_v2():
    print("STARTED TEST r1 sha256 VECTOR 2")
    test_signatures_secp256r1(
        hashfunc=sha256,
        msg="test",
        k='d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0',
        r=0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
        s=0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083
    )
    print("TEST r1 sha256 VECTOR 2 PASSED")

def test_signature_curve256r1_vectors():
    test_signatures_secp256r1_sha1_v1()
    test_signatures_secp256r1_sha1_v2()
    test_signatures_secp256r1_sha256_v1()
    test_signatures_secp256r1_sha256_v2()

print("STARTIN TESTS")
test_signature_validity_curve256k1_vectors()
test_signature_curve256r1_vectors()
print("TESTING DONE")
