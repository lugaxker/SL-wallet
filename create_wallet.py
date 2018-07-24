#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import sha3 # pysha3

from base58 import Base58
from crypto import *
from address import Address

BTC_P2PKH_VERBYTE = 0x00
DSH_P2PKH_VERBYTE = 0x4c

BCH_WIF_PREFIX = 0x80
BTC_WIF_PREFIX = 0x80
DSH_WIF_PREFIX = 0xcc

BTC_BIP44_TYPE = 0x00
BCH_BIP44_TYPE = 0x91
DSH_BIP44_TYPE = 0x05
ETH_BIP44_TYPE = 0x3c

def keccak256(x):
    return sha3.keccak_256( x ).digest()
    
def sha3_256(x):
    return hashlib.sha3_256( x ).digest()
    
def eth_checksum_encode( addr ): # hex address
    o = ''
    v = int.from_bytes( keccak256( addr.encode('utf-8') ), 'big')
    for i, c in enumerate( addr ):
        if c in '0123456789':
            o += c
        else:
            o += c.upper() if (v & (1 << (255 - 4*i))) else c.lower()
    return '0x' + o
    
def eth_test_checksum(addrstr):
    assert(addrstr == eth_checksum_encode(addrstr[2:].lower()))
    
def eth_pubkey_to_addr( pubkey ):
    assert( pubkey[0] == 0x04 )
    return eth_checksum_encode( keccak256( pubkey[1:] )[-20:].hex() )

def get_account( mxprv, coin, i ):
    ''' Returns extended keys (private and public) of the account i. '''
    if coin == "bch":
        coin_type = BCH_BIP44_TYPE
    elif coin == "btc":
        coin_type = BTC_BIP44_TYPE
    elif coin == "dsh":
        coin_type = DSH_BIP44_TYPE
    elif coin == "eth":
        coin_type = ETH_BIP44_TYPE
    else:
        raise ValueError("wrong type of coin: {}", coin)
    
    branch = "m"
    sequence = "m/44'/{:d}'/{:d}'".format(coin_type, i)
    return private_derivation(mxprv, branch, sequence)

def get_adresses_from_account( account_xpub, coin, addr_index, change ):
    if isinstance(addr_index, int):
        addr_index = [addr_index]
    branch_number = 1 if change else 0
    pubkeys = []
    addresses = []
    for i in addr_index:
        sequence = "/{:d}/{:d}".format(branch_number, i)
        xpub = public_derivation( account_xpub, "", sequence )
        cpubkey, _, _, _, _ = decode_xkey( xpub )

        if coin == "bch":
            pubkeys.append( cpubkey.hex() )
            addresses.append( Address.from_pubkey( cpubkey ).to_cash() )
        elif coin == "btc":
            pubkeys.append( cpubkey.hex() )
            addresses.append( Base58.encode_check( bytes([BTC_P2PKH_VERBYTE]) + hash160(cpubkey) ) )
        elif coin == "dsh":
            pubkeys.append( cpubkey.hex() )
            addresses.append( Base58.encode_check( bytes([DSH_P2PKH_VERBYTE]) + hash160(cpubkey) ) )
        elif coin == "eth":
            pubkey = PublicKey.from_ser( cpubkey )
            pubkey.uncompress()
            pubkeys.append( pubkey.to_ser(strtype=True) )
            addresses.append( eth_pubkey_to_addr( pubkey.to_ser() ) )
        else:
            raise ValueError("wrong type of coin: {}", coin)
    return addresses, pubkeys

def get_prvkeys_from_account( account_xprv, coin, addr_index, change ):
    if isinstance(addr_index, int):
        addr_index = [addr_index]
    branch_number = 1 if change else 0
    prvkeys = []
    for i in addr_index:
        sequence = "/{:d}/{:d}".format(branch_number, i)
        xprv, _ = private_derivation( account_xprv, "", sequence )
        prvkey, _, _, _, _ = decode_xkey( xprv )
        if coin == "bch":
            prvkeys.append( Base58.encode_check( bytes([BCH_WIF_PREFIX]) + prvkey + bytes([0x01]) ) )
        elif coin == "btc":
            prvkeys.append( Base58.encode_check( bytes([BTC_WIF_PREFIX]) + prvkey + bytes([0x01]) ) )
        elif coin == "dsh":
            prvkeys.append( Base58.encode_check( bytes([DSH_WIF_PREFIX]) + prvkey + bytes([0x01]) ) )
        elif coin == "eth":
            prvkeys.append( "0x" + prvkey.hex() )
        else:
            raise ValueError("wrong type of coin: {}", coin)
    
    return prvkeys



if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
        
    mnemonic = "zoo remove narrow bronze dizzy fashion scatter fossil ask clog bar slight"
    seed = seed_from_mnemonic( mnemonic )
    mxprv, mxpub = root_from_seed( seed )
    print("Mnemonic phrase:", mnemonic)
    print("Root (master extended private key and master extended public key)")
    print(" ", mxprv)
    print(" ", mxpub)
    
    # Create 3 external addresses (receiving addresses) for BCH, BTC, DSH and ETH
    n_addresses = 3
    coin = "eth"
    for coin in ["bch", "btc", "dsh", "eth"]:
        account_xprv, account_xpub = get_account(mxprv, coin, 0)
        addr_index = range(0, n_addresses)
        addresses, pubkeys = get_adresses_from_account( account_xpub, coin, addr_index, change=False )
        prvkeys = get_prvkeys_from_account(account_xprv, coin, addr_index, change=False)
        print()
        print("--- {} ---".format(coin.upper()))
        print("Adresses and associated public and private keys")
        for i in addr_index:
            print(" ", i, addresses[i], pubkeys[i], prvkeys[i] )
    
    print()
    print("Private and public keys")
    
    wifkey = "KxJGuUFJqtxvRSvYG74jHCr5ev6VBjtfiotFQay1e2rfzu5Vk8FN"
    k = PrivateKey.from_wif(wifkey)
    print( "wifkey", wifkey )
    signature = k.sign( sha256( "olala".encode("utf-8") ) )
    print(signature.hex())
    K = PublicKey.from_prvkey( wifkey )
    print("ser K", K.to_ser( strtype=True ) )
    print("address", Address.from_pubkey(K.to_ser()).to_cash() )
    
    
    