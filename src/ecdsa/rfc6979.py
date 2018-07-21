'''
RFC 6979:
    Deterministic Usage of the Digital Signature Algorithm (DSA) and
    Elliptic Curve Digital Signature Algorithm (ECDSA)

    http://tools.ietf.org/html/rfc6979

Many thanks to Coda Hale for his implementation in Go language:
    https://github.com/codahale/rfc6979
'''

import hmac
from six import b
import binascii
from binascii import hexlify

import sys, os
scriptPath = os.path.realpath(os.path.dirname(sys.argv[0]))
os.chdir(scriptPath)

#append the relative location you want to import from
sys.path.append(".")

#import your module stored in '../common'
# import util

from util import number_to_string, number_to_string_crop

try:
    bin(0)
except NameError:
    binmap = {"0": "0000", "1": "0001", "2": "0010", "3": "0011",
              "4": "0100", "5": "0101", "6": "0110", "7": "0111",
              "8": "1000", "9": "1001", "a": "1010", "b": "1011",
              "c": "1100", "d": "1101", "e": "1110", "f": "1111"}

    def bin(value):  # for python2.5
        v = "".join(binmap[x] for x in "%x" % abs(value)).lstrip("0")
        if value < 0:
            return "-0b" + v
        return "0b" + v


def bit_length(num):
    # http://docs.python.org/dev/library/stdtypes.html#int.bit_length
    s = bin(num)  # binary representation:  bin(-37) --> '-0b100101'
    s = s.lstrip('-0b')  # remove leading zeros and minus sign
    return len(s)  # len('100101') --> 6


def bits2int(data, qlen):
    x = int(hexlify(data), 16)
    l = len(data) * 8

    if l > qlen:
        return x >> (l - qlen)
    return x


def bits2octets(data, order):
    z1 = bits2int(data, bit_length(order))
    z2 = z1 - order

    if z2 < 0:
        z2 = z1

    return number_to_string_crop(z2, order)

def class_name(v):
    return type(v).__name__

def debug(value, variable_name):
    value_print_friendly = value
    if isinstance(value, bytes):
        value_print_friendly = 'hex=`{}`, int=`{}`'.format(str(binascii.hexlify(value), 'utf-8'), int.from_bytes(value, byteorder="big"))

    print('`{}`: `{}` = value=`{}`'.format(variable_name, class_name(value), value_print_friendly))


# https://tools.ietf.org/html/rfc6979#section-3.2
def generate_k(order, secexp, hash_func, data):
    '''
        order - order of the DSA generator used in the signature
        secexp - secure exponent (private key) in numeric form
        hash_func - reference to the same hash function used for generating hash
        data - hash in binary form of the signing data
    '''

    qlen = bit_length(order)
    holen = hash_func().digest_size
    rolen = (qlen + 7) / 8
    bx = number_to_string(secexp, order) + bits2octets(data, order)

    # debug(hex(order), 'input - `order`')
    # debug(data, 'input - `data`')
    # debug(hex(secexp), 'input - `secexp`')
    # debug(qlen, 'setup - `qlen`')
    # debug(holen, 'setup - `holen`')
    # debug(rolen, 'setup - `rolen`')
    # debug(bx, 'setup - `bx`')

    # Step B
    v = b('\x01') * holen

    # Step C
    k = b('\x00') * holen

    # Step D

    k = hmac.new(k, v + b('\x00') + bx, hash_func).digest()
    # debug(k, 'Step d - `k`')

    # Step E
    v = hmac.new(k, v, hash_func).digest()
    # debug(v, 'Step e - `v`')

    # Step F
    k = hmac.new(k, v + b('\x01') + bx, hash_func).digest()
    # debug(k, 'Step f - `k`')

    # Step G
    v = hmac.new(k, v, hash_func).digest()
    # debug(v, 'Step g - `v`')

    # Step H
    while True:
        # Step H1
        t = b('')

        # Step H2
        while len(t) < rolen:
            v = hmac.new(k, v, hash_func).digest()
            t += v

        # debug(t, 'Step h.2.END - `t`')
        # Step H3
        secret = bits2int(t, qlen)
        # debug(hex(secret), 'Step h.3.a - secret (`k`)')

        if secret >= 1 and secret < order:
            return secret

        k = hmac.new(k, v + b('\x00'), hash_func).digest()
        # debug(k, 'Step h.3.b - `k`')
        v = hmac.new(k, v, hash_func).digest()
        # debug(v, 'Step h.3.c - `v`')
