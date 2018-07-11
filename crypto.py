#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ecdsa
import hashlib
import hmac
from base58 import *

# Hash functions

def sha256(x):
    '''Simple wrapper of hashlib sha256.'''
    return hashlib.sha256(x).digest()

def dsha256(x):
    '''SHA-256 of SHA-256, as used extensively in bitcoin.'''
    return sha256(sha256(x))

def ripemd160(x):
    '''Simple wrapper of hashlib ripemd160.'''
    h = hashlib.new('ripemd160')
    h.update(x)
    return h.digest()

def hash160(x):
    '''RIPEMD-160 of SHA-256.'''
    return ripemd160(sha256(x))

def hmac_sha512(x, y):
    return hmac.new(x, y, hashlib.sha512).digest()

# Keys

WIF_PREFIX = 0x80

def ecc_getyfromx(x, curve = ecdsa.ecdsa.curve_secp256k1, odd=True):
    _p = curve.p()
    _a = curve.a()
    _b = curve.b()
    y2 = ( pow(x, 3, _p) + _a * pow(x, 2, _p) + _b ) % _p # y2 = x3 + 7 mod p
    y = pow(y2, (_p+1)//4, _p)
    if y == 0 or (not curve.contains_point(x,y)):
        raise ValueError("no y value for {:d}".format(x))
    
    if bool(y % 2) == odd:
        return y
    else:
        return (_p - y)

def point_to_ser(P, compressed):
    if compressed:
        return bytes.fromhex( "{:02x}{:064x}".format( 2+(P.y()&1), P.x() ) )
    return bytes.fromhex( "04{:064x}{:064x}".format(P.x(), P.y()) )
    
def ser_to_point(s):
    curve = ecdsa.ecdsa.curve_secp256k1
    generator = ecdsa.ecdsa.generator_secp256k1
    
    prefix = s[0]
    payload = s[1:]
    x = int.from_bytes( s[1:33] ,'big')
    assert prefix in [0x02, 0x03, 0x04]
    if prefix == 0x04:
        y = int.from_bytes( s[33:] ,'big')
    else:
        y = ecc_getyfromx(x, curve, prefix == 0x03)
    return ecdsa.ellipticcurve.Point( curve, x, y, generator.order() )

class ModifiedSigningKey(ecdsa.SigningKey):
    '''Enforce low S values in signatures (BIP-62).'''

    def sign_number(self, number, entropy=None, k=None):
        curve = ecdsa.SECP256k1
        G = curve.generator
        order = G.order()
        r, s = ecdsa.SigningKey.sign_number(self, number, entropy, k)
        if s > order//2:
            s = order - s
        return r, s

class EllipticCurveKey:
    
    def __init__( self, k, compressed=True ):
        secret = ecdsa.util.string_to_number(k)
        self.pubkey = ecdsa.ecdsa.Public_key( ecdsa.ecdsa.generator_secp256k1, ecdsa.ecdsa.generator_secp256k1 * secret )
        self.privkey = ecdsa.ecdsa.Private_key( self.pubkey, secret )
        self.secret = secret
        self.compressed = compressed
    
    @classmethod
    def from_wifkey(self, wifkey ):
        vch = Base58.decode_check( wifkey )
        assert len(vch) in (33,34)
        if vch[0] != WIF_PREFIX:
            raise BaseError('wrong version byte for WIF private key')
        k = vch[1:33]
        compressed = (len(vch) == 34)
        return self( k, compressed )
    
    def to_wifkey(self):
        payload = bytes([WIF_PREFIX]) + self.secret.to_bytes(32, 'big')
        if self.compressed:
            payload += bytes([0x01])
        return Base58.encode_check( payload )
            
    def sign(self, msg_hash):
        private_key = ModifiedSigningKey.from_secret_exponent(self.secret, curve = ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        signature = private_key.sign_digest_deterministic(msg_hash, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der)
        assert public_key.verify_digest(signature, msg_hash, sigdecode = ecdsa.util.sigdecode_der)        
        return signature
    
    def serialize_pubkey(self):
        return point_to_ser(self.pubkey.point, self.compressed)


        