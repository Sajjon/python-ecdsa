from .ecdsa import (Private_key, Public_key, Signature,
                    curve_192, generator_192,
                    digest_integer, ellipticcurve, point_is_valid)
from .keys import SigningKey, VerifyingKey
from .curves import NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1
from hashlib import sha3_256
from . import rfc6979
import binascii
from six import print_
import random

def public_address_from_vk(vk):
    pubkey = vk.to_string()
    pubkey_sha3_256 = sha3_256(pubkey)
    pk_bytes_all = pubkey_sha3_256.digest()
    rightmost_20bytes = pk_bytes_all[12:32]
    public_addr = binascii.hexlify(rightmost_20bytes)

    print_("public key")
    print_(binascii.hexlify(pubkey))

    print_("ALT1 LEFTMOST public address:")
    print_(binascii.hexlify(pk_bytes_all[0:20]))

    return public_addr

# class RFC6979(unittest.TestCase):
    # https://tools.ietf.org/html/rfc6979#appendix-A.1
# def test_understand():
#     curve = SECP256k1
#     sk = SigningKey.generate(curve=curve)
#     sk_string = sk.to_string()
#     sk_string_hex = binascii.hexlify(sk_string)
#     sk_string_from_hex = binascii.unhexlify(sk_string_hex)
#     assert sk_string_from_hex == sk_string
#     sk2 = SigningKey.from_string(sk_string, curve=curve)
#     assert sk2.to_string() == sk_string

#     print_("💚 TEST SUCCESSFUL 💚")
#     print_("sk_string_hex:")
#     print_(sk_string_hex)

#     vk = sk.verifying_key

#     print_("public key")
#     print_(binascii.hexlify(vk.to_string()))

#     print_("public address:")
#     print_(public_address_from_vk(vk))
#     assert 1 == 2

def class_name(v):
    return type(v).__name__

def test_sk2pk():
    sk_numb = int("cc7d1263009ebbc8e31f5b7e7d79b625e57cf489cd540e1b0ac4801c8daab9be", 16)

    fmt_str = "%0" + str(64) + "x"
    sk_string = binascii.unhexlify((fmt_str % sk_numb).encode())
    sk_string_hex = binascii.hexlify(sk_string)

    sk = SigningKey.from_string(sk_string, curve=SECP256k1)

    assert sk.to_string() == sk_string
    vk = sk.verifying_key
    print_("💚 TEST SUCCESSFUL 💚")
    print_("Private key: %s" % (sk_string_hex))
    print_(public_address_from_vk(vk))
    assert 1 == 2