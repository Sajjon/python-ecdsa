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


def test_deterministic_signatures(
    curve,
    privateKey,
    msg,
    expectedK,
    expectedR=None,
    expectedS=None,
    expectedDER=None,
    hashfunc=sha256,
    ensure_low_s_according_to_bip62=True):
    
    msg = msg.encode('utf-8')
    privateKey = int(privateKey, 16)
    signing_key = SigningKey.from_secret_exponent(privateKey, curve)
    (k, der) = signing_key.sign_deterministic(msg, hashfunc=hashfunc, sigencode=sigencode_der, ensure_low_s_according_to_bip62=ensure_low_s_according_to_bip62)
    kHex = format(k, 'x')
    assert kHex == expectedK, "Deterministic K mismatch, expected {}, but got {}".format(expectedK, kHex)
    r, s = sigdecode_der(der, curve.order)
    rHex = format(r, 'x')
    sHex = format(s, 'x')
    derHex = binascii.hexlify(der).decode("utf-8")

    # print("k: {}, expected: {}".format(kHex, expectedK))
    # print("r: {}".format(rHex, expectedR))
    # print("s: {}".format(sHex, expectedS))
    # print("der: {}".format(derHex, expectedDER))

    if expectedDER != None:
        assert derHex == expectedDER, "Signature mismatch, expected {}, but got {}".format(expectedDER, derHex)
    
    if expectedR != None:
        assert rHex == expectedR, "Signature R mismatch, expected {}, but got {}".format(expectedR, rHex)

    if expectedS != None:
        assert sHex == expectedS, "Signature S mismatch, expected {}, but got {}".format(expectedS, SHex)


def test_signatures_secp256k1(
    privateKey,
    msg,
    expectedK,
    expectedR=None,
    expectedS=None,
    expectedDER=None,
    ensure_low_s_according_to_bip62=True): 
    test_deterministic_signatures(
        SECP256k1,
        privateKey,
        msg,
        expectedK,
        expectedR,
        expectedS, 
        expectedDER,
        ensure_low_s_according_to_bip62=ensure_low_s_according_to_bip62
    )

def test_signatures_secp256r1(
    hashfunc,
    msg,
    expectedK,
    expectedR,
    expectedS,
    expectedDER=None,
    ensure_low_s_according_to_bip62=False):
    test_deterministic_signatures(
        NIST256p,
        'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721',
        msg,
        expectedK,
        expectedR,
        expectedS,
        expectedDER,
        hashfunc=hashfunc,
        ensure_low_s_according_to_bip62=ensure_low_s_according_to_bip62
    )

# TEST VECTORS FROM: https://github.com/trezor/trezor-crypto/blob/957b8129bded180c8ac3106e61ff79a1a3df8893/tests/test_check.c#L1959-L1965
# But signature results from: https://github.com/oleganza/CoreBitcoin/blob/master/CoreBitcoinTestsOSX/BTCKeyTests.swift
# Regarding: `ensure_low_s_according_to_bip62`
# https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures
# https://bitcoin.stackexchange.com/questions/38252/the-complement-of-s-when-s-curve-order-2
# https://bitcoin.stackexchange.com/questions/50980/test-r-s-values-for-signature-generation
# https://bitcointalk.org/index.php?topic=285142.msg3299061#msg3299061
def test_signatures_secp256k1_v1():
    test_signatures_secp256k1(
        privateKey='cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50',
        msg="sample",
        expectedK='2df40ca70e639d89528a6b670d9d48d9165fdc0febc0974056bdce192b8e16a3',
        expectedR='af340daf02cc15c8d5d08d7735dfe6b98a474ed373bdb5fbecf7571be52b3842',
        expectedS='5009fb27f37034a9b24b707b7c6b79ca23ddef9e25f7282e8a797efe53a8f124',
        expectedDER='3045022100af340daf02cc15c8d5d08d7735dfe6b98a474ed373bdb5fbecf7571be52b384202205009fb27f37034a9b24b707b7c6b79ca23ddef9e25f7282e8a797efe53a8f124'
    )


def test_signatures_secp256k1_v2():
    print("STARTED TEST VECTOR 2")
    test_signatures_secp256k1(
        privateKey='0000000000000000000000000000000000000000000000000000000000000001',
        msg="Satoshi Nakamoto",
        expectedK='8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15',
        expectedR='934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8',
        expectedS='2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5',
        expectedDER='3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5',
    )

def test_signatures_secp256k1_v3():
    print("STARTED TEST VECTOR 3")
    test_signatures_secp256k1(
        privateKey='fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
        msg="Satoshi Nakamoto",
        expectedK='33a19b60e25fb6f4435af53a3d42d493644827367e6453928554f43e49aa6f90',
        expectedR='fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d0',
        expectedS='6b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5',
        expectedDER='3045022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d002206b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5',
    )

def test_signatures_secp256k1_v4():
    print("STARTED TEST VECTOR 4")
    test_signatures_secp256k1(
        privateKey='f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181',
        msg="Alan Turing",
        expectedK='525a82b70e67874398067543fd84c83d30c175fdc45fdeee082fe13b1d7cfdf1',
        expectedR='7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c',
        expectedS='58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea',
        expectedDER='304402207063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c022058dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea'
    )

def test_signatures_secp256k1_v5():
    print("STARTED TEST VECTOR 5")
    test_signatures_secp256k1(
        privateKey='0000000000000000000000000000000000000000000000000000000000000001',
        msg="All those moments will be lost in time, like tears in rain. Time to die...",
        expectedK='38aa22d72376b4dbc472e06c3ba403ee0a394da63fc58d88686c611aba98d6b3',
        expectedR='8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b',
        expectedS='547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21',
        expectedDER='30450221008600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b0220547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21'
    )

def test_signatures_secp256k1_v6():
    print("STARTED TEST VECTOR 6")
    test_signatures_secp256k1(
        privateKey='e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2',
        msg="There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
        expectedK='1f4b84c23a86a221d233f2521be018d9318639d5b8bbd6374a8a59232d16ad3d',
        expectedR='b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b',
        expectedS='279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6',
        expectedDER='3045022100b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b0220279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6'
    )

def test_signature_validity_curve256k1_vectors():
    test_signatures_secp256k1_v1() 
    test_signatures_secp256k1_v2() 
    test_signatures_secp256k1_v3() 
    test_signatures_secp256k1_v4() 
    test_signatures_secp256k1_v5() 
    test_signatures_secp256k1_v6()

# https://tools.ietf.org/html/rfc6979#appendix-A.2.5
def test_signatures_secp256r1_sha1_v1():
    print("STARTED TEST r1 sha1 VECTOR 1")
    test_signatures_secp256r1(
        hashfunc=sha1,
        msg="sample",
        expectedK='882905f1227fd620fbf2abf21244f0ba83d0dc3a9103dbbee43a1fb858109db4',
        expectedR='61340c88c3aaebeb4f6d667f672ca9759a6ccaa9fa8811313039ee4a35471d32',
        expectedS='6d7f147dac089441bb2e2fe8f7a3fa264b9c475098fdcf6e00d7c996e1b8b7eb',
        # DER not from test vector, but derived by this code
        expectedDER='3044022061340c88c3aaebeb4f6d667f672ca9759a6ccaa9fa8811313039ee4a35471d3202206d7f147dac089441bb2e2fe8f7a3fa264b9c475098fdcf6e00d7c996e1b8b7eb'
    )

# https://tools.ietf.org/html/rfc6979#appendix-A.2.5
def test_signatures_secp256r1_sha1_v2():
    print("STARTED TEST r1 sha1 VECTOR 2")
    test_signatures_secp256r1(
        hashfunc=sha1,
        msg="test",
        expectedK='8c9520267c55d6b980df741e56b4adee114d84fbfa2e62137954164028632a2e',
        expectedR='cbcc86fd6abd1d99e703e1ec50069ee5c0b4ba4b9ac60e409e8ec5910d81a89',
        expectedS='1b9d7b73dfaa60d5651ec4591a0136f87653e0fd780c3b1bc872ffdeae479b1',
        # DER not from test vector, but derived by this code
        expectedDER='304402200cbcc86fd6abd1d99e703e1ec50069ee5c0b4ba4b9ac60e409e8ec5910d81a89022001b9d7b73dfaa60d5651ec4591a0136f87653e0fd780c3b1bc872ffdeae479b1'
   )

def test_signatures_secp256r1_sha256_v1():
    print("STARTED TEST r1 sha256 VECTOR 1")
    test_signatures_secp256r1(
        hashfunc=sha256,
        msg="sample",
        expectedK='a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60',
        expectedR='efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716',
        expectedS='f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
        # DER not from test vector, but derived by this code
        expectedDER='3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8'
   )


def test_signatures_secp256r1_sha256_v2():
    print("STARTED TEST r1 sha256 VECTOR 2")
    test_signatures_secp256r1(
        hashfunc=sha256,
        msg="test",
        expectedK='d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0',
        expectedR='f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367',
        expectedS='19f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083',
        # DER not from test vector, but derived by this code
        expectedDER='3045022100f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d383670220019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083'
   )

def test_signature_curve256r1_vectors():
    test_signatures_secp256r1_sha1_v1()
    test_signatures_secp256r1_sha1_v2()
    test_signatures_secp256r1_sha256_v1()
    test_signatures_secp256r1_sha256_v2()

print("STARTING TESTS")
test_signature_validity_curve256k1_vectors()
test_signature_curve256r1_vectors()
print("TESTING DONE")
