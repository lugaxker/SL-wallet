#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import hmac
import pbkdf2

import ecdsa

from base58 import Base58
from crypto import (hmac_sha512, EllipticCurveKey, ecc_getyfromx, point_to_ser, ser_to_point)

XPRV_HEADER = 0x0488ade4
XPUB_HEADER = 0x0488b21e

def mnemonic_to_seed(mnemonic, passphrase = ""):
    ''' Compute BIP-39 seed from BIP-39 mnemonic phrase. Passphrase is optional. '''
    return pbkdf2.PBKDF2(mnemonic, "mnemonic" + passphrase, iterations = 2048, macmodule = hmac, digestmodule = hashlib.sha512).read(64)

def encode_xkey(chain_code, key, depth = 0, fingerprint=b'\x00'*4, child_number=b'\x00'*4):
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
        raise BaseException('Invalid extended key format')
    return chain_code, key, depth, fingerprint, child_number

def CKD_prv(kpar, cpar, index):
    ''' Child key derivation from a private key (BIP-32). '''
    assert len(kpar) == 32
    hardened = (index > 0x80000000)
    if hardened:
        key_and_index = bytes([0]) + kpar + index.to_bytes(4,'big')
    else:
        eckey = EllipticCurveKey( kpar, True )
        key_and_index = eckey.serialize_pubkey() + index.to_bytes(4,'big')
    I = hmac_sha512(cpar, key_and_index)
    order = ecdsa.ecdsa.generator_secp256k1.order()
    ki = ( (int.from_bytes(I[0:32], 'big') + int.from_bytes(kpar, 'big') ) % order ).to_bytes(32, 'big')
    ci = I[32:]
    return ki, ci

def CKD_pub(Kpar, cpar, index):
    ''' Child key derivation from a compressed public key (BIP-32). '''
    assert len(Kpar) == 33
    if index > 0x80000000:
        raise BaseException('Hardened derivation cannot results from a public key')
    key_and_index = Kpar + index.to_bytes(4,'big')
    I = hmac_sha512(cpar, key_and_index)
    pt_G = ecdsa.SECP256k1.generator
    pt_K = ser_to_point(Kpar)
    pt_Ki = int.from_bytes(I[0:32],'big') * pt_G + pt_K
    Ki = point_to_ser(pt_Ki, True)
    ci = I[32:]
    return Ki, ci

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    # BIP-39 mnemonic phrase: hundred garage genius weekend echo explain deal swamp kitchen crunch rigid lyrics
    # BIP-39 seed: 923f4490a96a1de7fb21150be66ea57e93311bc47900eec571be5abed344bbf90ce72cbb2e8a51e65ec36c7d6701802cecb0766b20bf3df37899c3fb95ac8249
    # BIP-32 root key: xprv9s21ZrQH143K27eKKfiNJLPJSX8oYi8AP8VM7CRtCRiHxrJjG28RzjtoGrHZm5vh58uTmL2ExHUgoi2Z6zVZsLRzhMuAkSPuBCwtvcp6Dbr
    # BIP-32 extended key: xprv9yE7utbAWFFM4VnbS2qBGJdzYkBceyb8DPKTtBoigQMnpQPhVDt1mfidaJww3ut9eMn1zwRDKsQwiPz93dkCrZREJHw8aSSgDbbtaFZEaiF
    
    mnemonic = "hundred garage genius weekend echo explain deal swamp kitchen crunch rigid lyrics"
    
    seed = mnemonic_to_seed(mnemonic)
    print(seed.hex())
    
    I = hmac_sha512(b"Bitcoin seed", seed)
    master_k = I[0:32]
    assert ( 0 < int.from_bytes(master_k,'big') < ecdsa.ecdsa.generator_secp256k1.order() )
    master_c = I[32:]
    print(master_k.hex())
    print(master_c.hex())
    
    eckey = EllipticCurveKey( master_k, True )
    master_K = eckey.serialize_pubkey()
    print( eckey.to_wifkey() )
    
    # Extended keys    
    master_xprv = encode_xkey(master_c, master_k)
    master_xpub = encode_xkey(master_c, master_K)
    print(master_xprv, master_xpub)
    
    #chain_code, key, depth, fingerprint, child_number = decode_xkey( master_xprv )
    
    # Child key derivation (show xprv xpub ?)
    print()
    print("Child key derivation from the master private key")
    k_0, c_0 = CKD_prv(master_k, master_c, 0)
    eckey_0 = EllipticCurveKey( k_0, True )
    print(" private key m/0", eckey_0.to_wifkey() )
    print(" public key m/0", eckey_0.serialize_pubkey().hex())
    k_1, c_1 = CKD_prv(master_k, master_c, 1)
    eckey_1 = EllipticCurveKey( k_1, True )
    print(" private key m/1", eckey_1.to_wifkey() )
    
    print()
    print("Child key derivation from private key m/0")
    k_0_0, c_0_0 = CKD_prv(k_0, c_0, 0)
    eckey_0_0 = EllipticCurveKey( k_0_0, True )
    print(" private key m/0/0",eckey_0_0.to_wifkey() )
    
    print()
    print("Child key derivation from the master public key")
    K_0, _ = CKD_pub(master_K, master_c, 0)
    print(" public key m/0", K_0.hex())
    
