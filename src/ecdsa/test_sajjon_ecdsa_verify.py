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

def test_signature_validity(curve, generator, Msg, Qx, Qy, R, S, expectedVerification):
    """Msg = message, Qx and Qy represent the base point on
       elliptic curve c192, R and S are the signature, and
       "expected" is True iff the signature is expected to be valid."""
    pubk = Public_key(generator, ellipticcurve.Point(curve, Qx, Qy))
    verificationRes = pubk.verifies(digest_integer(Msg), Signature(R, S))
    assert verificationRes == expectedVerification, "Signature verification failed"


# def test_signature_validity_curve192(Msg, Qx, Qy, R, S, expected):
    # test_signature_validity(curve_192, generator_192, Msg, Qx, Qy, R, S, expected)

def test_sign_val_192_v1():
    Msg = 0x84ce72aa8699df436059f052ac51b6398d2511e49631bcb7e71f89c499b9ee425dfbc13a5f6d408471b054f2655617cbbaf7937b7c80cd8865cf02c8487d30d2b0fbd8b2c4e102e16d828374bbc47b93852f212d5043c3ea720f086178ff798cc4f63f787b9c2e419efa033e7644ea7936f54462dc21a6c4580725f7f0e7d158
    Qx = 0xd9dbfb332aa8e5ff091e8ce535857c37c73f6250ffb2e7ac
    Qy = 0x282102e364feded3ad15ddf968f88d8321aa268dd483ebc4
    R = 0x64dca58a20787c488d11d6dd96313f1b766f2d8efe122916
    S = 0x1ecba28141e84ab4ecad92f56720e2cc83eb3d22dec72479
    test_signature_validity_curve192(Msg, Qx, Qy, R, S, True)

def test_sign_val_192_v2():
    Msg = 0x94bb5bacd5f8ea765810024db87f4224ad71362a3c28284b2b9f39fab86db12e8beb94aae899768229be8fdb6c4f12f28912bb604703a79ccff769c1607f5a91450f30ba0460d359d9126cbd6296be6d9c4bb96c0ee74cbb44197c207f6db326ab6f5a659113a9034e54be7b041ced9dcf6458d7fb9cbfb2744d999f7dfd63f4
    Qx = 0x3e53ef8d3112af3285c0e74842090712cd324832d4277ae7
    Qy = 0xcc75f8952d30aec2cbb719fc6aa9934590b5d0ff5a83adb7
    R = 0x8285261607283ba18f335026130bab31840dcfd9c3e555af
    S = 0x356d89e1b04541afc9704a45e9c535ce4a50929e33d7e06c
    test_signature_validity_curve192(Msg, Qx, Qy, R, S, True)

def test_sign_val_192_v3():
    Msg = 0xf6227a8eeb34afed1621dcc89a91d72ea212cb2f476839d9b4243c66877911b37b4ad6f4448792a7bbba76c63bdd63414b6facab7dc71c3396a73bd7ee14cdd41a659c61c99b779cecf07bc51ab391aa3252386242b9853ea7da67fd768d303f1b9b513d401565b6f1eb722dfdb96b519fe4f9bd5de67ae131e64b40e78c42dd
    Qx = 0x16335dbe95f8e8254a4e04575d736befb258b8657f773cb7
    Qy = 0x421b13379c59bc9dce38a1099ca79bbd06d647c7f6242336
    R = 0x4141bd5d64ea36c5b0bd21ef28c02da216ed9d04522b1e91
    S = 0x159a6aa852bcc579e821b7bb0994c0861fb08280c38daa09
    test_signature_validity_curve192(Msg, Qx, Qy, R, S, False)

def test_sign_val_192_v4():
    Msg = 0x16b5f93afd0d02246f662761ed8e0dd9504681ed02a253006eb36736b563097ba39f81c8e1bce7a16c1339e345efabbc6baa3efb0612948ae51103382a8ee8bc448e3ef71e9f6f7a9676694831d7f5dd0db5446f179bcb737d4a526367a447bfe2c857521c7f40b6d7d7e01a180d92431fb0bbd29c04a0c420a57b3ed26ccd8a
    Qx = 0xfd14cdf1607f5efb7b1793037b15bdf4baa6f7c16341ab0b
    Qy = 0x83fa0795cc6c4795b9016dac928fd6bac32f3229a96312c4
    R = 0x8dfdb832951e0167c5d762a473c0416c5c15bc1195667dc1
    S = 0x1720288a2dc13fa1ec78f763f8fe2ff7354a7e6fdde44520
    test_signature_validity_curve192(Msg, Qx, Qy, R, S, False)

def test_signature_validity_curve192_vectors():
    test_sign_val_192_v1() 
    test_sign_val_192_v2() 
    test_sign_val_192_v3() 
    test_sign_val_192_v4()

def class_name(v):
    return type(v).__name__

def debug(value, variable_name):
    value_print_friendly = value
    if isinstance(value, bytes):
        value_print_friendly = 'hex=`{}`, int=`{}`'.format(str(binascii.hexlify(value), 'utf-8'), int.from_bytes(value, byteorder="big"))

    print('`{}`: `{}` = value=`{}`'.format(variable_name, class_name(value), value_print_friendly))


print("STARTIN TESTS")
test_signature_validity_curve192_vectors()
print("TESTING DONE")
