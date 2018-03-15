#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ecdsa
import hashlib
from base58 import *

def sha256(x):
    '''Simple wrapper of hashlib sha256.'''
    return hashlib.sha256(x).digest()

def double_sha256(x):
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

# Keys

WIF_PREFIX = 0x80

class EllipticCurveKey:
    
    def __init__( self, k, compressed=False ):
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
            
    def sign(self, msg_hash):
        private_key = ecdsa.SigningKey.from_secret_exponent(self.secret, curve = ecdsa.curves.SECP256k1)
        public_key = private_key.get_verifying_key()
        signature = private_key.sign_digest_deterministic(msg_hash, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der)
        assert public_key.verify_digest(signature, msg_hash, sigdecode = ecdsa.util.sigdecode_der)
        
        #pre_hash = Hash(bfh(self.serialize_preimage(i)))
        #pkey = regenerate_key(sec)
        #secexp = pkey.secret
        #private_key = MySigningKey.from_secret_exponent(secexp, curve = SECP256k1)
        #public_key = private_key.get_verifying_key()
        #sig = private_key.sign_digest_deterministic(pre_hash, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der)
        
        
        return signature
    
    def serialized_pubkey(self):
        P = self.pubkey.point
        if self.compressed:
            return bytes.fromhex( "{:02x}{:064x}".format( 2+(P.y()&1), P.x() ) )
        return bytes.fromhex( "04{:064x}{:064x}".format(P.x(), P.y()) )