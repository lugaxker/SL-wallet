#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (EllipticCurveKey, seed_from_mnemonic, root_from_seed, decode_xkey, private_derivation, public_derivation)
from mnemonic import generate_mnemonic



if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
        
    # https://iancoleman.io/bip39/
    # BIP-39 mnemonic phrase: hundred garage genius weekend echo explain deal swamp kitchen crunch rigid lyrics
    # BIP-39 seed: 923f4490a96a1de7fb21150be66ea57e93311bc47900eec571be5abed344bbf90ce72cbb2e8a51e65ec36c7d6701802cecb0766b20bf3df37899c3fb95ac8249
    # BIP-32 root key: xprv9s21ZrQH143K27eKKfiNJLPJSX8oYi8AP8VM7CRtCRiHxrJjG28RzjtoGrHZm5vh58uTmL2ExHUgoi2Z6zVZsLRzhMuAkSPuBCwtvcp6Dbr
    
    nbits = 128
    random_mnemonic = generate_mnemonic(nbits)
    print("Random mnemonic phrase ({} words): {}".format((nbits + nbits//32) // 11, random_mnemonic))
    
    mnemonic = "hundred garage genius weekend echo explain deal swamp kitchen crunch rigid lyrics"
    mnemonic = "repeat chaos salon trash omit index indoor nephew catch blood come weather"
    print("Mnemonic phrase:", mnemonic)
    
    seed = seed_from_mnemonic(mnemonic, "")
    print("Seed", seed.hex())
    
    mxprv, mxpub = root_from_seed( seed )
    print()
    print("Master keys")
    print(" xprv", mxprv)
    print(" xpub", mxpub)
        
    # Child key derivation (show xprv xpub ?)
    print()
    print("Child key derivation from the master private key (m)")
    xprv_0, xpub_0 = private_derivation(mxprv, "m", "m/0")
    print(" xprv m/0", xprv_0 )
    print(" xpub M/0", xpub_0 )
    k_0, _, _, _, _ = decode_xkey(xprv_0)
    K_0, _, _, _, _ = decode_xkey(xpub_0)
    print(" private key m/0", EllipticCurveKey( k_0, True ).to_wifkey() )
    print(" public key M/0", K_0.hex())
    
    print()
    print("Hardened child key derivation from the master private key (m)")
    xprv_0, xpub_0 = private_derivation(mxprv, "m", "m/0'")
    print(" xprv m/0'", xprv_0 )
    print(" xpub M/0'", xpub_0 )
    k_0, _, _, _, _ = decode_xkey(xprv_0)
    K_0, _, _, _, _ = decode_xkey(xpub_0)
    print(" private key m/0'", EllipticCurveKey( k_0, True ).to_wifkey() )
    print(" public key M/0'", K_0.hex())
    
    print()
    print("BIP-44 first BTC account")
    branch = "m"
    sequence = "m/44'/0'/0'"
    xprv_account, xpub_account = private_derivation(mxprv, branch, sequence)
    print(" xprv {}".format(sequence), xprv_account )
    print(" xpub {}".format("M" + sequence[1:]), xpub_account )
    k_account, _, _, _, _ = decode_xkey(xprv_account)
    K_account, _, _, _, _ = decode_xkey(xpub_account)
    print(" private key {}".format(sequence), EllipticCurveKey( k_account, True ).to_wifkey() )
    print(" public key {}".format(sequence), K_account.hex())
    
    print()
    print("BIP-44 first external address of the first BTC account")
    branch = "m"
    sequence = "m/44'/0'/0'/0/0"
    xprv_bip_144, xpub_bip_144 = private_derivation(mxprv, branch, sequence)
    print(" xprv {}".format(sequence), xprv_bip_144 )
    print(" xpub {}".format("M" + sequence[1:]), xpub_bip_144 )
    k_bip_144, _, _, _, _ = decode_xkey(xprv_bip_144)
    K_bip_144, _, _, _, _ = decode_xkey(xpub_bip_144)
    print(" private key {}".format(sequence), EllipticCurveKey( k_bip_144, True ).to_wifkey() )
    print(" public key {}".format(sequence), K_bip_144.hex())

    print()
    print("Public derivation")
    xprv_44_0_0, xpub_44_0_0 = private_derivation(mxprv, "m", "m/44'/0'/0'")
    xpub_44_0_0_0_0 = public_derivation( xpub_44_0_0, "m/44'/0'/0'", "m/44'/0'/0'/0/0" )
    print(" xpub m/44'/0'/0'/0/0", xpub_44_0_0_0_0)
    K_44_0_0_0_0, _, _, _, _ = decode_xkey( xpub_44_0_0_0_0 )
    print(" public key m/44'/0'/0'/0/0", K_44_0_0_0_0.hex())
    
    print()
    print("Dash keys and address")
    branch = "m/"
    sequence = "m/44'/5'/0'/0/0"
    xprv_dash, xpub_dash = private_derivation(mxprv, branch, sequence)
    k_dash, _, _, _, _ = decode_xkey(xprv_dash)
    K_dash, _, _, _, _ = decode_xkey(xpub_dash)
    
    from base58 import Base58
    from constants import dsh_mainnet
    payload = bytes([dsh_mainnet.WIF_PREFIX]) + k_dash + bytes([0x01])
    wifkey_dash = Base58.encode_check( payload )
    print(" private key {}".format(sequence), wifkey_dash)
    print(" public key {}".format(sequence), K_dash.hex())
    from crypto import hash160
    dash_address = Base58.encode_check( bytes([0x4c]) + hash160(K_dash) )
    print(" dash address {}".format(sequence), dash_address)
