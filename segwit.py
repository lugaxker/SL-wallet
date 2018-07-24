#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (sha256, hash160, PrivateKey, PublicKey)
from base58 import Base58
from address import Address
from script import push_data, multisig_locking_script

class SegWitAddr:
    """ Reference implementation for Bech32 and segwit addresses. """
    # Copyright (c) 2017 Pieter Wuille
    
    SEGWIT_HRP = "bc"
    
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    @staticmethod
    def bech32_polymod(values):
        """Internal function that computes the Bech32 checksum."""
        generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ value
            for i in range(5):
                chk ^= generator[i] if ((top >> i) & 1) else 0
        return chk
    
    @staticmethod
    def bech32_hrp_expand(hrp):
        """Expand the HRP into values for checksum computation."""
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    @staticmethod
    def bech32_verify_checksum(hrp, data):
        """Verify a checksum given HRP and converted data characters."""
        return SegWitAddr.bech32_polymod(SegWitAddr.bech32_hrp_expand(hrp) + data) == 1
    
    @staticmethod
    def bech32_create_checksum(hrp, data):
        """Compute the checksum values given HRP and data."""
        values = SegWitAddr.bech32_hrp_expand(hrp) + data
        polymod = SegWitAddr.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

    @staticmethod
    def bech32_encode(hrp, data):
        """Compute a Bech32 string given HRP and data values."""
        combined = data + SegWitAddr.bech32_create_checksum(hrp, data)
        return hrp + '1' + ''.join([SegWitAddr.CHARSET[d] for d in combined])
    
    @staticmethod
    def bech32_decode(bech):
        """Validate a Bech32 string, and determine HRP and data."""
        if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
                (bech.lower() != bech and bech.upper() != bech)):
            return (None, None)
        bech = bech.lower()
        pos = bech.rfind('1')
        if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
            return (None, None)
        if not all(x in SegWitAddr.CHARSET for x in bech[pos+1:]):
            return (None, None)
        hrp = bech[:pos]
        data = [SegWitAddr.CHARSET.find(x) for x in bech[pos+1:]]
        if not SegWitAddr.bech32_verify_checksum(hrp, data):
            return (None, None)
        return (hrp, data[:-6])

    @staticmethod
    def convertbits(data, frombits, tobits, pad=True):
        """General power-of-2 base conversion."""
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        for value in data:
            if value < 0 or (value >> frombits):
                return None
            acc = ((acc << frombits) | value) & max_acc
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        return ret

    @staticmethod
    def decode(hrp, addr):
        """Decode a segwit address."""
        hrpgot, data = SegWitAddr.bech32_decode(addr)
        if hrpgot != hrp:
            return (None, None)
        decoded = SegWitAddr.convertbits(data[1:], 5, 8, False)
        if decoded is None or len(decoded) < 2 or len(decoded) > 40:
            return (None, None)
        if data[0] > 16:
            return (None, None)
        if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
            return (None, None)
        return (data[0], decoded)

    @staticmethod
    def encode(hrp, witver, witprog):
        """Encode a segwit address."""
        ret = SegWitAddr.bech32_encode(hrp, [witver] + SegWitAddr.convertbits(witprog, 8, 5))
        assert SegWitAddr.decode(hrp, ret) is not (None, None)
        return ret

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    # Private key
    wifkey = "KzwQjFQPytv5x6w2cLdF4BSweGVCPEt8b8HbcuTi8e75LRQfw94L"
    
    # Public key and address (Public Key Hash)
    pubkey = PublicKey.from_prvkey( wifkey ).to_ser()
    addr = Address.from_pubkey( pubkey )
    print( "Private Key (WIF)", wifkey )
    print( "Legacy Address (P2PKH)", addr.to_legacy() )
    
    # Witness version (0)
    witver = 0
    
    # Native segwit P2WPKH address
    segaddr = SegWitAddr.encode( SegWitAddr.SEGWIT_HRP, witver, addr.hash_addr )
    print("SegWit Address (P2WPKH)", segaddr)
    
    # P2SH-nested segwit P2WPKH address
    witness_script = bytes([witver]) + push_data( addr.hash_addr )
    segaddr_p2sh = Address.from_script( witness_script )
    print("SegWit Address (P2WPKH-P2SH)", segaddr_p2sh.to_legacy() )
    
    # Native P2WSH multisig address
    wifkeys_multisig = ["KzwQjFQPytv5x6w2cLdF4BSweGVCPEt8b8HbcuTi8e75LRQfw94L",
                        "Ky4yk7uTBZ1EDbqyVfkvoZXURpWdRCxTpCERZb4gkn67fY8kK95R",
                        "Kz3Htg8mSfC997qkBxpVCdxYhEoRcFj5ikUjE96ipVAJPou7MwRD"]
    pubkeys =  [PublicKey.from_prvkey( wk ).to_ser() for wk in wifkeys_multisig ]
    print()
    print("--- 2-of-3 multisig address ---")
    print("Private keys")
    for wk in wifkeys_multisig:
        print("", wk)
    redeem_script = multisig_locking_script(pubkeys, 2)
    redeem_script_hash = sha256( redeem_script )
    print("SHA256 of redeem script", redeem_script_hash.hex())
    print("Legacy Address (P2SH)", Address.from_script( redeem_script ).to_legacy())
    
    p2wsh_addr = SegWitAddr.encode( SegWitAddr.SEGWIT_HRP, witver, redeem_script_hash )
    print("SegWit Address (P2WSH)", p2wsh_addr)
    