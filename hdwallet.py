#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ecdsa

from crypto import *


    
if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    # https://iancoleman.io/bip39/
    # BIP-39 mnemonic phrase: hundred garage genius weekend echo explain deal swamp kitchen crunch rigid lyrics
    # BIP-39 seed: 923f4490a96a1de7fb21150be66ea57e93311bc47900eec571be5abed344bbf90ce72cbb2e8a51e65ec36c7d6701802cecb0766b20bf3df37899c3fb95ac8249
    # BIP-32 root key: xprv9s21ZrQH143K27eKKfiNJLPJSX8oYi8AP8VM7CRtCRiHxrJjG28RzjtoGrHZm5vh58uTmL2ExHUgoi2Z6zVZsLRzhMuAkSPuBCwtvcp6Dbr
    # BIP-32 extended key: xprv9yE7utbAWFFM4VnbS2qBGJdzYkBceyb8DPKTtBoigQMnpQPhVDt1mfidaJww3ut9eMn1zwRDKsQwiPz93dkCrZREJHw8aSSgDbbtaFZEaiF
    
    mnemonic = "hundred garage genius weekend echo explain deal swamp kitchen crunch rigid lyrics"
    
    seed = mnemonic_to_seed(mnemonic, "")
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
    master_xprv = encode_xkey(master_k, master_c)
    master_xpub = encode_xkey(master_K, master_c)
    print(master_xprv, master_xpub)
        
    # Child key derivation (show xprv xpub ?)
    print()
    print("Child key derivation from the master private key (m)")
    xprv_0, xpub_0 = private_derivation(master_xprv, "m", "m/0")
    print(" xprv m/0", xprv_0 )
    print(" xpub M/0", xpub_0 )
    k_0, _, _, _, _ = decode_xkey(xprv_0)
    K_0, _, _, _, _ = decode_xkey(xpub_0)
    print(" private key m/0", EllipticCurveKey( k_0, True ).to_wifkey() )
    print(" public key M/0", K_0.hex())
    
    print()
    print("Hardened child key derivation from the master private key (m)")
    xprv_0, xpub_0 = private_derivation(master_xprv, "m", "m/0'")
    print(" xprv m/0'", xprv_0 )
    print(" xpub M/0'", xpub_0 )
    k_0, _, _, _, _ = decode_xkey(xprv_0)
    K_0, _, _, _, _ = decode_xkey(xpub_0)
    print(" private key m/0'", EllipticCurveKey( k_0, True ).to_wifkey() )
    print(" public key M/0'", K_0.hex())
    
    print()
    print("BIP-44 first external address of the first BTC account")
    branch = "m"
    sequence = "m/44'/0'/0'/0/0"
    print("({})".format(sequence))
    xprv_bip_144, xpub_bip_144 = private_derivation(master_xprv, branch, sequence)
    print(" xprv m/0", xprv_bip_144 )
    print(" xpub M/0", xpub_bip_144 )
    k_bip_144, _, _, _, _ = decode_xkey(xprv_bip_144)
    K_bip_144, _, _, _, _ = decode_xkey(xpub_bip_144)
    print(" private key {}".format(sequence), EllipticCurveKey( k_bip_144, True ).to_wifkey() )
    print(" public key {}".format(sequence), K_bip_144.hex())

    print()
    print("Public derivation")
    xprv_44_0_0, xpub_44_0_0 = private_derivation(master_xprv, "m", "m/44'/0'/0'")
    xpub_44_0_0_0_0 = public_derivation( xpub_44_0_0, "m/44'/0'/0'", "m/44'/0'/0'/0/0" )
    print(" xpub m/44'/0'/0'/0/0", xpub_44_0_0_0_0)
    K_44_0_0_0_0, _, _, _, _ = decode_xkey( xpub_44_0_0_0_0 )
    print(" public key m/44'/0'/0'/0/0", K_44_0_0_0_0.hex())
    
