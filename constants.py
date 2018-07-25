#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class Constants:
    '''Bitcoin Cash network constants.'''
    
    BIP32_HARDENED = 0x80000000
    CASH_P2PKH = 0x00
    CASH_P2SH = 0x08 >> 3
    
    FEE_RATE = 1 # in sat per byte (sat/B)
    
    @classmethod
    def set_mainnet(self):
        ''' Main network. '''
        self.WIF_PREFIX = 0x80
        self.LEGACY_P2PKH = 0x00
        self.LEGACY_P2SH = 0x05
        self.CASH_HRP = "bitcoincash"
        
        self.XPRV_HEADER = 0x0488ade4
        self.XPUB_HEADER = 0x0488b21e
        
        self.BIP44_TYPE = 0x91
    
    @classmethod
    def set_testnet(self):
        ''' Test network. '''
        self.WIF_PREFIX = 0xef
        self.LEGACY_P2PKH = 0x6f
        self.LEGACY_P2SH = 0xc4
        self.CASH_HRP = "bchtest"
        
        self.XPRV_HEADER = 0x043587cf
        self.XPUB_HEADER = 0x04358394
        
        self.BIP44_TYPE = 0x01
        
Constants.set_mainnet()