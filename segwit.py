#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (sha256, dsha256, hash160, PrivateKey, PublicKey)
from base58 import Base58
from address import Address
from util import (push_data, var_int)
from script import multisig_locking_script
from transaction import Transaction

from constants import *

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
    
    
def segwit_locking_script(witver, witprog):
    return bytes([witver]) + push_data(witprog)

class BtcTransaction(Transaction):
    
    BTC_SIGHASH_TYPE = 0x01
    
    def __init__(self, version = Constants.TX_VERSION, txins = [], txouts = [], locktime = 0):
        self._inputs = txins
        self._outputs = txouts
        self.version = version
        self.locktime = locktime
        self.hashtype = self.BTC_SIGHASH_TYPE # hardcoded signature hashtype
    
    def serialize_legacy_preimage(self):
        ''' Serializes the preimage of the transaction.'''
        nVersion = self.version.to_bytes(4,'little')
        nLocktime = self.locktime.to_bytes(4,'little')
        nHashtype = self.hashtype.to_bytes(4,'little') # signature hashtype (little-endian)
        
        txins = var_int(len(self._inputs))
        for txin in self._inputs:
            outpoint  = self.serialize_outpoint(txin)
            prevLockingScript = self.get_preimage_script(txin)
            prevLockingScriptSize = var_int( len(prevLockingScript) )
            nSequence = txin['sequence'].to_bytes(4,'little')
            txins += outpoint + prevLockingScriptSize + prevLockingScript + nSequence
        txouts = var_int(len(self._outputs)) + bytes().join( self.serialize_output(txo) for txo in self._outputs )
        
        return (nVersion + txins + txouts + nLocktime + nHashtype)
    
    def sign(self, private_keys):
        '''Signs the transaction. 
        prvkeys (list of PrivateKey items)'''
        for i, txin in enumerate(self._inputs):
            prvkeys = private_keys[i] 
            if isinstance( prvkeys, PrivateKey):
                assert txin['nsigs'] == 1
                prvkeys = [ prvkeys ]
            elif isinstance( prvkeys, list ):
                assert len( prvkeys ) == txin['nsigs']
                # Sorting keys
                sorted_prvkeys = []
                for prvkey in prvkeys:
                    pubkey = PublicKey.from_prvkey( prvkey )
                    assert(pubkey in txin['pubkeys'])
                    sorted_prvkeys += [(txin['pubkeys'].index(pubkey), prvkey)]
                sorted_prvkeys.sort(key = lambda x: x[0])
                prvkeys = [k[1] for k in sorted_prvkeys]
            else:
                raise TransactionError('wrong type for private keys')
            if txin['type'] in ('p2pkh','p2sh'):
                prehash = dsha256( self.serialize_legacy_preimage() )
            elif txin['type'] in ('p2wpkh', 'p2wsh', 'p2sh-p2wpkh', 'p2sh-p2wsh'):
                prehash = dsha256( self.serialize_preimage(txin) )
            hashtype = bytes( [self.hashtype & 0xff] ).hex()
            self._inputs[i]['signatures'] = [ prvkey.sign( prehash, strtype=True ) + hashtype for prvkey in prvkeys ]
    

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    # Private key
    wifkey = "Kzczf8E4oq8MLakhRS479gpZpSe2e6u2xErKHQNqpeFMPEK4irtc"
    
    # Public key and address (Public Key Hash)
    pubkey = PublicKey.from_prvkey( wifkey ).to_ser()
    addr = Address.from_pubkey( pubkey )
    print( "Private Key (WIF)", wifkey )
    print( "Legacy Address (P2PKH)", addr.to_legacy() )
    
    # Witness version (0)
    witver = 0
    
    # Witness program
    witprog_p2wpkh = addr.h 
    
    # Native segwit P2WPKH address
    segaddr = SegWitAddr.encode( SegWitAddr.SEGWIT_HRP, witver, witprog_p2wpkh )
    print("SegWit Address (P2WPKH)", segaddr)
    
    # P2SH-nested segwit P2WPKH address
    witness_script = segwit_locking_script( witver, witprog_p2wpkh )
    segaddr_p2sh = Address.from_script( witness_script )
    print("SegWit Address (P2SH-P2WPKH)", segaddr_p2sh.to_legacy() )
    print()
    
    # P2WSH multisig address
    wifkeys_multisig = ["KzwQjFQPytv5x6w2cLdF4BSweGVCPEt8b8HbcuTi8e75LRQfw94L",
                        "Ky4yk7uTBZ1EDbqyVfkvoZXURpWdRCxTpCERZb4gkn67fY8kK95R",
                        "Kz3Htg8mSfC997qkBxpVCdxYhEoRcFj5ikUjE96ipVAJPou7MwRD"]
    pubkeys =  [PublicKey.from_prvkey( wk ) for wk in wifkeys_multisig ]
    print("--- 2-of-3 multisig address ---")
    print("Private keys")
    for wk in wifkeys_multisig:
        print("", wk)
    redeem_script = multisig_locking_script(pubkeys, 2)
    redeem_script_hash = sha256( redeem_script )
    print("SHA256 of redeem script", redeem_script_hash.hex())
    print("Legacy Address (P2SH)", Address.from_script( redeem_script ).to_legacy())
    
    # Witness program 
    witprog_p2wsh = redeem_script_hash
    
    # Native segwit P2WSH address
    p2wsh_addr = SegWitAddr.encode( SegWitAddr.SEGWIT_HRP, witver, witprog_p2wsh )
    print("SegWit Address (P2WSH)", p2wsh_addr)
    
    # P2SH-nested segwit P2WPKH address
    witness_script = segwit_locking_script( witver, witprog_p2wsh )
    segaddr_p2sh_p2wsh = Address.from_script( witness_script )
    print("SegWit Address (P2SH-P2WSH)", segaddr_p2sh_p2wsh.to_legacy() )
    print()
    
    print("-----")
    h = bytes.fromhex("914a1f77b4bf763b901655e52e83784d5c605053")
    witver = 0
    witprog = h
    witness_script = segwit_locking_script(witver, witprog)
    a = Address.from_script(witness_script).to_legacy()
    print(a)

    redeem_script_hash = bytes.fromhex("04d3da43f6750398281ed128d23bc6b6daa90e3c7431d15acaee052b0e6351be")
    witprog = redeem_script_hash
    p2wsh_addr = SegWitAddr.encode( SegWitAddr.SEGWIT_HRP, witver, witprog )
    print("SegWit Address (P2WSH)", p2wsh_addr)

    h = bytes.fromhex("2a44a5921e7e62e84e4478c2dd836dbfc9732bae87")
    witver = 0
    witprog = h
    script = segwit_locking_script(witver, witprog)
    a = Address.from_script(script).to_legacy()
    print(a)

    redeem_script = bytes.fromhex("522102472b25609c0089b28774009b187c6558adc03115b81cb9387ecd14f4d49a62ca2103dbc2f6b9337ff9565916733c8614d8bb673104c5c8e3bdd5453b04cd8dd22e2e52ae")
    hash_redeem_script = sha256( redeem_script )
    print(hash_redeem_script.hex(), "=?", redeem_script_hash.hex(), ("Oui" if hash_redeem_script == redeem_script_hash else "Non"))

    redeem_script_2 = bytes.fromhex("6321035ddbc3ec6a9459ab05e20af1451d80deff37941095b2003ecc27c0235a8dc4d067029000b2752102d7c52ff0e21c77a848fe5b2eb1cd68a1ad4d84dfeacd2c1ec141d66f4364772868ac")
    hash_redeem_script_2 = sha256( redeem_script_2 )
    witprog = hash_redeem_script_2
    p2wsh_addr_2 = SegWitAddr.encode( SegWitAddr.SEGWIT_HRP, witver, witprog )
    print(p2wsh_addr_2)
    print()
    
    
    # BTC transaction
    wifkey = "KxDEKVUyDvbZj2sCoiKjpPKHuz7Vcei7t4PL1wiapTnQTAgLdNrb"
    prvkey = PrivateKey.from_wif( wifkey )
    pubkey = PublicKey.from_prvkey( prvkey )
    address = Address.from_pubkey( pubkey ) # 1QKcNhS3VmDfbaAoX8gZpKuM3Xr9gZ8Pxo
    print()
    print("BTC legacy transaction")
    print("Keys", prvkey, pubkey)
    print("Address", address.to_legacy() )
    output_address = Address.from_string("37KwYRZUteFURrfYiKDg21dGWvf8K1wcNm")
    print("Output address", output_address.to_legacy())
    
    # Inputs
    txins = []
    
    txin1 = {}
    txin1['address'] = address
    txin1['type'] = 'p2pkh'
    txin1['sequence'] = Constants.SEQUENCE_NUMBER
    txin1['pubkeys'] = [ pubkey ]
    txin1['nsigs'] = 1
    txin1['txid'] = "8a61b19482340bfc5e479875c649f08accf6d6488f138fb86d60dc0e14bfe827"
    txin1['index'] = 0
    txin1['value'] = 3300
    txins.append( txin1 )
    
    # Output
    txout = {}
    txout['address'] = output_address
    txout['type'] = 'p2sh'
    txout['value'] = 2800
    
    tx = BtcTransaction(1, txins, [txout], 0)
    tx.sign( [ prvkey ] )
    
    print(tx.serialize().hex())
    print("id:", tx.txid().hex())