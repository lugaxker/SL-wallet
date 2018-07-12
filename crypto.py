#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ecdsa
import hashlib
import hmac
import pbkdf2
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
    
# Key Derivation

class KeyDerivationError(Exception):
    '''Exception used for key derivation errors.'''
    
XPRV_HEADER = 0x0488ade4
XPUB_HEADER = 0x0488b21e
HARDENED = 0x80000000

def seed_from_mnemonic( mnemonic, passphrase = "" ):
    ''' Compute BIP-39 seed from BIP-39 mnemonic phrase. Passphrase is optional. '''
    return pbkdf2.PBKDF2(mnemonic, "mnemonic" + passphrase, iterations = 2048, macmodule = hmac, digestmodule = hashlib.sha512).read(64)

def root_from_seed( seed ):
    ''' Compute BIP-32 root (master extended keys) from seed. '''
    I = hmac_sha512(b"Bitcoin seed", seed)
    master_private_key = I[0:32]
    if not ( 0 < int.from_bytes(master_private_key,'big') < ecdsa.ecdsa.generator_secp256k1.order() ):
        raise KeyDerivationError("wrong seed: master private key must be lower than ec generator order")
    master_chain_code = I[32:]
    master_public_key = EllipticCurveKey( master_private_key, compressed=True ).serialize_pubkey()
    xprv = encode_xkey( master_private_key, master_chain_code )
    xpub = encode_xkey( master_public_key, master_chain_code )
    return xprv, xpub

def encode_xkey(key, chain_code, depth = 0, fingerprint=b'\x00'*4, child_number=b'\x00'*4):
    assert len(key) in (32,33)
    if len(key) == 32:
        payload = XPRV_HEADER.to_bytes(4, 'big') + bytes([depth]) + fingerprint + child_number + chain_code + bytes([0x00]) + key
    elif len(key) == 33:
        payload = XPUB_HEADER.to_bytes(4, 'big') + bytes([depth]) + fingerprint + child_number + chain_code + key
    return Base58.encode_check( payload )

def decode_xkey( xkey ):
    payload = Base58.decode_check( xkey )
    assert len(payload) == 78
    header = int.from_bytes(payload[0:4], 'big')
    depth = payload[4]
    fingerprint = payload[5:9]
    child_number = payload[9:13]
    chain_code = payload[13:45]
    
    assert ( header in (XPRV_HEADER, XPUB_HEADER) )
    if header == XPRV_HEADER:
        key = payload[46:]
    elif header == XPUB_HEADER:
        key = payload[45:]
    else:
        raise KeyDerivationError('Invalid extended key format')
    return key, chain_code, depth, fingerprint, child_number

def xpub_from_xprv( xprv ):
    prvkey, chain_code, depth, fingerprint, child_number = decode_xkey( xprv )
    pubkey = EllipticCurveKey( kpar, compressed=True ).serialize_pubkey()
    return encode_xkey(pubkey, chain_code, depth, fingerprint, child_number)

def CKD_prv(kpar, cpar, index):
    ''' Child key derivation from a private key (BIP-32). '''
    assert len(kpar) == 32
    hardened = (index >= HARDENED)
    if hardened:
        key_and_index = bytes([0]) + kpar + index.to_bytes(4,'big')
    else:
        Kpar = EllipticCurveKey( kpar, compressed=True ).serialize_pubkey()
        key_and_index = Kpar + index.to_bytes(4,'big')
    I = hmac_sha512(cpar, key_and_index)
    order = ecdsa.ecdsa.generator_secp256k1.order()
    ki = ( (int.from_bytes(I[0:32], 'big') + int.from_bytes(kpar, 'big') ) % order ).to_bytes(32, 'big')
    ci = I[32:]
    return ki, ci

def CKD_pub(Kpar, cpar, index):
    ''' Child key derivation from a compressed public key (BIP-32). '''
    assert len(Kpar) == 33
    if index >= HARDENED:
        raise KeyDerivationError("Derivation from a public key cannot be hardened")
    key_and_index = Kpar + index.to_bytes(4,'big')
    I = hmac_sha512(cpar, key_and_index)
    pt_G = ecdsa.SECP256k1.generator
    pt_K = ser_to_point(Kpar)
    pt_Ki = int.from_bytes(I[0:32],'big') * pt_G + pt_K
    Ki = point_to_ser(pt_Ki, True)
    ci = I[32:]
    return Ki, ci

def private_derivation(xprv, branch, sequence):
    ''' BIP-32 private derivation. 
    xprv (str): extended private key 
    branch (str): for example m
    sequence (str): for example m/0'/0 '''
    assert sequence.startswith(branch)
    if sequence == branch:
        return xprv, xpub_from_xprv( xprv )
    sequence = sequence[len(branch):]
    
    k, c, depth, _ , _ = decode_xkey( xprv )
    for n in sequence.split("/"):
        if n == "": continue
        index = int(n[:-1]) + HARDENED if n[-1] == "'" else int(n)
        kpar = k
        cpar = c
        k, c = CKD_prv(kpar, cpar, index)
        depth += 1
    Kpar = EllipticCurveKey(kpar, compressed=True).serialize_pubkey()
    fingerprint = hash160(Kpar)[0:4]
    child_number = index.to_bytes(4,'big')
    K = EllipticCurveKey(k, compressed=True).serialize_pubkey()
    xprv = encode_xkey(k, c, depth, fingerprint, child_number)
    xpub = encode_xkey(K, c, depth, fingerprint, child_number)
    return xprv, xpub

def public_derivation(xpub, branch, sequence):
    ''' BIP-32 public derivation. Cannot be hardened. 
    xpub (str): extended public key 
    branch (str): for example m
    sequence (str): for example m/0/0 '''
    assert sequence.startswith(branch)
    if sequence == branch:
        return xpub
    sequence = sequence[len(branch):]
    if "'" in sequence: 
        raise KeyDerivationError("Derivation from a public key cannot be hardened")
    
    K, c, depth, _ , _ = decode_xkey( xpub )
    for n in sequence.split("/"):
        if n == "": continue
        index = int(n)
        Kpar = K
        cpar = c
        K, c = CKD_pub(Kpar, cpar, index)
        depth += 1
    fingerprint = hash160(Kpar)[0:4]
    child_number = index.to_bytes(4,'big')
    return encode_xkey(K, c, depth, fingerprint, child_number)
        