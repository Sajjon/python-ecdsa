# from __future__ import with_statement, division

#first change the cwd to the script path
import sys, os
scriptPath = os.path.realpath(os.path.dirname(sys.argv[0]))
os.chdir(scriptPath)

#append the relative location you want to import from
sys.path.append(".")

#import your module stored in '../common'
import rfc6979

# import unittest
# import os
# import time
# import shutil
# import subprocess
# from binascii import hexlify, unhexlify
from hashlib import sha1, sha256, sha512

from six import b, print_, binary_type
# # from .keys import SigningKey, VerifyingKey
# # from .keys import BadSignatureError
# # from . import util
# from .util import sigencode_der, sigencode_strings
# from .util import sigdecode_der, sigdecode_strings
# from .curves import Curve, UnknownCurveError
# from .curves import NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1
# from .ellipticcurve import Point
# from . import der
# from . import rfc6979

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

import hashlib
import binascii

def generateNonceK(privkey, msg):
	data = msg.encode('utf-8')
	hashed = sha256(data).digest()
	d = int(privkey, 16)
	k = rfc6979.generate_k(n, d, sha256, hashed)
	kHex = format(k, 'x')
	return kHex

def test_6979(privkey, msg, expectedKNonce, expectedSign):
	k = generateNonceK(privkey=privkey, msg=msg)
	assert expected == k, 'k was `{}`'.format(k)

# TEST VECTORS FROM HERE: https://github.com/trezor/trezor-crypto/blob/957b8129bded180c8ac3106e61ff79a1a3df8893/tests/test_check.c#L1959-L1965
def test_vector1():
	test_6979(
		'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
		'sample',
		'a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60',
		'3045022100af340daf02cc15c8d5d08d7735dfe6b98a474ed373bdb5fbecf7571be52b384202205009fb27f37034a9b24b707b7c6b79ca23ddef9e25f7282e8a797efe53a8f124'
	)
	print("TEST VECTOR 1 PASSED")

# def test_vector2():
# 	test_6979(
# 		'cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50',
# 		'sample',
# 		'2df40ca70e639d89528a6b670d9d48d9165fdc0febc0974056bdce192b8e16a3'
# 	)
# 	print("TEST VECTOR 2 PASSED")


# def test_vector3():
# 	test_6979(
# 		'0000000000000000000000000000000000000000000000000000000000000001',
# 		'Satoshi Nakamoto',
# 		'8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15'
# 	)
# 	print("TEST VECTOR 3 PASSED")


# def test_vector4():
# 	test_6979(
# 		'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
# 		'Satoshi Nakamoto',
# 		'33a19b60e25fb6f4435af53a3d42d493644827367e6453928554f43e49aa6f90'
# 	)
# 	print("TEST VECTOR 4 PASSED")


# def test_vector5():
# 	test_6979(
# 		'f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181',
# 		'Alan Turing',
# 		'525a82b70e67874398067543fd84c83d30c175fdc45fdeee082fe13b1d7cfdf1'
# 	)
# 	print("TEST VECTOR 5 PASSED")


# def test_vector6():
# 	test_6979(
# 		'0000000000000000000000000000000000000000000000000000000000000001',
# 		'All those moments will be lost in time, like tears in rain. Time to die...',
# 		'38aa22d72376b4dbc472e06c3ba403ee0a394da63fc58d88686c611aba98d6b3'
# 	)
# 	print("TEST VECTOR 6 PASSED")


# def test_vector7():
# 	test_6979(
# 		'e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2',
# 		"There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
# 		'1f4b84c23a86a221d233f2521be018d9318639d5b8bbd6374a8a59232d16ad3d'
# 	)
# 	print("TEST VECTOR 7 PASSED")

def run_all_tests():
	test_vector1()
	# test_vector2()
	# test_vector3()
	# test_vector4()
	# test_vector5()
	# test_vector6()
	# test_vector7()

print("RUNNING TESTS")
run_all_tests()
print("TESTS FINISHED")