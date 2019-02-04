#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ecdsa
import hashlib
import hmac
import pbkdf2

from base58 import *
from util import read_bytes

from constants import *

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

def getrandrange(order, entropy=None):
    return ecdsa.util.randrange(order, entropy)

class ModifiedSigningKey(ecdsa.SigningKey):
    ''' Enforce low S values in signatures (BIP-62). '''

    def sign_number(self, number, entropy=None, k=None):
        curve = ecdsa.SECP256k1
        G = curve.generator
        order = G.order()
        r, s = ecdsa.SigningKey.sign_number(self, number, entropy, k)
        if s > order//2:
            s = order - s
        return r, s

class PrivateKey:
    
    def __init__(self, secret, compressed=True):
        self.secret = secret
        self.compressed = compressed
    
    @classmethod
    def from_hex(self, k, compressed=True ):
        ''' Builds Private Key from 32-byte hex string. '''
        assert isinstance( k, (bytes, str))
        if isinstance( k, str ):
            k = bytes.fromhex( k )
        secret = int.from_bytes( k, 'big' )
        return self(secret, compressed)
        
    @classmethod
    def from_wif(self, wifkey):
        ''' Builds Private Key from Wallet Import Format string. '''
        assert isinstance( wifkey, str )
        payload = Base58.decode_check( wifkey )
        assert len(payload) in (33,34)
        if payload[0] != Constants.WIF_PREFIX:
            raise ValueError('wrong version byte for WIF private key')
        secret = int.from_bytes( payload[1:33], 'big' )
        compressed = (len(payload) == 34)
        return self( secret, compressed )
    
    def to_wif(self):
        payload = bytes([Constants.WIF_PREFIX]) + self.secret.to_bytes(32, 'big')
        if self.compressed:
            payload += bytes([0x01])
        return Base58.encode_check( payload )
    
    def sign(self, msg_hash, strtype=False):
        private_key = ModifiedSigningKey.from_secret_exponent(self.secret, curve = ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        signature = private_key.sign_digest_deterministic(msg_hash, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der)
        assert public_key.verify_digest(signature, msg_hash, sigdecode = ecdsa.util.sigdecode_der)        
        return ( signature.hex() if strtype else signature )
    
    def __str__(self):
        return self.to_wif()

    def __repr__(self):
        return '<PrivateKey {}>'.format(self.to_wif())
    
class PublicKey:
    
    def __init__(self, prefix, x, y=None):
        self.x = x
        self.y = y
        self.prefix = prefix
        
    def __eq__(self, other):
        return ( self.prefix == other.prefix ) & ( self.x == other.x ) & ( self.y == other.y )

    def __ne__(self, other):
        return ( self.prefix != other.prefix ) | ( self.x != other.x ) | ( self.y != other.y )
    
    @classmethod
    def from_prvkey(self, key, compressed=True):
        if isinstance(key, str):
            prvkey = PrivateKey.from_hex(key, compressed) if len(key) == 64 else PrivateKey.from_wif( key )
        elif isinstance(key, bytes):
            prvkey = PrivateKey.from_hex(key, compressed)
        elif isinstance(key, int):
            prvkey = PrivateKey(key, compressed)
        elif isinstance(key, PrivateKey):
            prvkey = key
        else:
            raise TypeError("Wrong type {0!r}".format(key))
        ec_point = ecdsa.ecdsa.Public_key( ecdsa.ecdsa.generator_secp256k1, ecdsa.ecdsa.generator_secp256k1 * prvkey.secret ).point
        if prvkey.compressed:
            return self( 0x02 + (ec_point.y() & 1), ec_point.x(), None )
        else:
            return self( 0x04, ec_point.x(), ec_point.y() )
    
    @classmethod
    def from_ser(self, serkey):
        ''' From serialized public key. '''
        assert isinstance( serkey, (bytes, str) )
        if isinstance( serkey, str ):
            serkey = bytes.fromhex( serkey )
        assert len(serkey) in (33, 65)
        prefix = serkey[0]
        assert prefix in (0x02, 0x03, 0x04)
        x = int.from_bytes( serkey[1:33], 'big' )
        y = int.from_bytes( serkey[34:], 'big' ) if prefix == 0x04 else None
        return self( prefix, x, y )
        
    @classmethod
    def from_ec_point(self, P, compressed=True):
        if compressed:
            return self( 0x02 + (P.y() & 1), P.x(), None)
        else:
            return self( 0x04, P.x(), P.y() )
    
    @staticmethod
    def _getyfromx(x, curve = ecdsa.ecdsa.curve_secp256k1, odd=True):
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
    
    def to_ser(self, strtype=False):
        if self.prefix == 0x04:
            s = "04{:064x}{:064x}".format(self.x, self.y)
        else:
            s = "{:02x}{:064x}".format( self.prefix, self.x )
        return ( s if strtype else bytes.fromhex(s) )
        
    def to_ec_point(self):
        curve = ecdsa.ecdsa.curve_secp256k1
        generator = ecdsa.ecdsa.generator_secp256k1
        x = self.x
        y = self.y if self.prefix == 0x04 else self._getyfromx(x, curve, self.prefix == 0x03)
        return ecdsa.ellipticcurve.Point( curve, x, y, generator.order() )
    
    def compress(self):
        if self.prefix == 0x04:
            self.prefix = 0x02 + (self.y & 1)
            self.y = None
    
    def uncompress(self):
        if self.prefix in (0x02, 0x03): 
            self.y = self._getyfromx(self.x, ecdsa.ecdsa.curve_secp256k1, self.prefix == 0x03)
            self.prefix = 0x04
            
    def is_compressed(self):
        return self.prefix in (0x02,0x03)
            
    def __str__(self):
        return self.to_ser(strtype=True)

    def __repr__(self):
        return '<PublicKey {}>'.format(self.to_ser(strtype=True))

    
# Key Derivation

class KeyDerivationError(Exception):
    '''Exception used for key derivation errors.'''

def seed_from_mnemonic( mnemonic, passphrase = "" ):
    ''' Compute BIP-39 seed from BIP-39 mnemonic phrase. Passphrase is optional. '''
    return pbkdf2.PBKDF2(mnemonic, "mnemonic" + passphrase, iterations = 2048, macmodule = hmac, digestmodule = hashlib.sha512).read(64)

def encode_xkey(key, chain_code, depth = 0, fingerprint=b'\x00'*4, child_number=b'\x00'*4):
    assert len(key) in (32,33)
    if len(key) == 32:
        payload = Constants.XPRV_HEADER.to_bytes(4, 'big') + bytes([depth]) + fingerprint + child_number + chain_code + bytes([0x00]) + key
    elif len(key) == 33:
        payload = Constants.XPUB_HEADER.to_bytes(4, 'big') + bytes([depth]) + fingerprint + child_number + chain_code + key
    return Base58.encode_check( payload )

def decode_xkey( xkey ):
    payload = Base58.decode_check( xkey )
    assert len(payload) == 78
    header, payload = read_bytes(payload, 4, int, 'big')
    depth, payload = read_bytes(payload, 1, int, 'big')
    fingerprint, payload = read_bytes(payload, 4, bytes, 'big')
    child_number, payload = read_bytes(payload, 4, bytes, 'big')
    chain_code, payload = read_bytes(payload, 32, bytes, 'big')
    
    if header == Constants.XPRV_HEADER:
        dummy, payload = read_bytes(payload, 1, int, 'big')
        assert dummy == 0
        key, payload = read_bytes(payload, 32, bytes, 'big')
    elif header == Constants.XPUB_HEADER:
        key, payload = read_bytes(payload, 33, bytes, 'big')
    else:
        raise KeyDerivationError('Invalid extended key format')
    assert payload == bytes()
    return key, chain_code, depth, fingerprint, child_number

def root_from_seed( seed ):
    ''' Compute BIP-32 root (master extended keys) from seed. '''
    I = hmac_sha512(b"Bitcoin seed", seed)
    master_prvkey = I[0:32]
    if not ( 0 < int.from_bytes(master_prvkey,'big') < ecdsa.ecdsa.generator_secp256k1.order() ):
        raise KeyDerivationError("wrong seed: master private key must be lower than ec generator order")
    master_chain_code = I[32:]
    master_pubkey = PublicKey.from_prvkey( master_prvkey ).to_ser()
    xprv = encode_xkey( master_prvkey, master_chain_code )
    xpub = encode_xkey( master_pubkey, master_chain_code )
    return xprv, xpub

def xpub_from_xprv( xprv ):
    ''' Gets extended public key from extended private key. '''
    prvkey, chain_code, depth, fingerprint, child_number = decode_xkey( xprv )
    pubkey = PublicKey.from_prvkey( prvkey ).to_ser()
    return encode_xkey(pubkey, chain_code, depth, fingerprint, child_number)

def CKD_prv(kpar, cpar, index):
    ''' Child key derivation from a private key (BIP-32). '''
    assert len(kpar) == 32
    if index >= Constants.BIP32_HARDENED:
        key_and_index = bytes([0]) + kpar + index.to_bytes(4,'big')
    else:
        Kpar = PublicKey.from_prvkey( kpar ).to_ser()
        key_and_index = Kpar + index.to_bytes(4,'big')
    I = hmac_sha512(cpar, key_and_index)
    order = ecdsa.ecdsa.generator_secp256k1.order()
    ki = ( (int.from_bytes(I[0:32], 'big') + int.from_bytes(kpar, 'big') ) % order ).to_bytes(32, 'big')
    ci = I[32:]
    return ki, ci

def CKD_pub(Kpar, cpar, index):
    ''' Child key derivation from a compressed public key (BIP-32). '''
    assert len(Kpar) == 33
    if index >= Constants.BIP32_HARDENED:
        raise KeyDerivationError("Derivation from a public key cannot be hardened")
    key_and_index = Kpar + index.to_bytes(4,'big')
    I = hmac_sha512(cpar, key_and_index)
    pt_G = ecdsa.ecdsa.generator_secp256k1
    pt_K = PublicKey.from_ser( Kpar ).to_ec_point()
    pt_Ki = int.from_bytes(I[0:32],'big') * pt_G + pt_K
    Ki = PublicKey.from_ec_point( pt_Ki ).to_ser()
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
        index = int(n[:-1]) + Constants.BIP32_HARDENED if n[-1] == "'" else int(n)
        kpar = k
        cpar = c
        k, c = CKD_prv(kpar, cpar, index)
        depth += 1
    Kpar = PublicKey.from_prvkey( kpar ).to_ser()
    fingerprint = hash160(Kpar)[0:4]
    child_number = index.to_bytes(4,'big')
    K = PublicKey.from_prvkey( k ).to_ser()
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
        