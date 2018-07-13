#!/usr/bin/env python3
# -*- coding: utf-8 -*-

XPRV_HEADER = 0x0488ade4
XPUB_HEADER = 0x0488b21e
BIP32_HARDENED = 0x80000000

class bch_mainnet:
    '''Bitcoin Cash main network constants.'''
    WIF_PREFIX = 0x80
    P2PKH_VERBYTE = 0x00
    P2SH_VERBYTE = 0x05
    
    BIP44_TYPE = 0x91
    
class bch_testnet:
    '''Bitcoin Cash test network constants.'''
    WIF_PREFIX = 0xef
    
    BIP44_TYPE = 0x01
    
class btc_mainnet:
    '''Bitcoin Core main network constants.'''
    WIF_PREFIX = 0x80
    
class btc_testnet:
    '''Bitcoin Core test network constants.'''
    WIF_PREFIX = 0xef
    
    BIP44_TYPE = 0x01
    
class dsh_mainnet:
    '''Dash main network constants.'''
    WIF_PREFIX = 0xcc
    
    BIP44_TYPE = 0x05
    
class dsh_testnet:
    '''Dash test network constants.'''
    BIP44_TYPE = 0x01
    
class ltc_mainnet:
    '''Litecoin main network constants.'''
    BIP44_TYPE = 0x02
    
class ltc_testnet:
    '''Litecoin test network constants.'''
    BIP44_TYPE = 0x01