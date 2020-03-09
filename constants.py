#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class Constants:
    '''Bitcoin Cash network constants.'''
    
    PROTOCOL_VERSION = 70015
    TX_VERSION = 2 # Version 2 enables sequence time locks (BIP-68)
    
    # Sequence flags
    SEQUENCE_FINAL = 0xffffffff
    SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31)
    SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)
    SEQUENCE_LOCKTIME_GRANULARITY = 9
    
    SEQUENCE_NUMBER = SEQUENCE_FINAL - 1
    
    BIP32_HARDENED = 0x80000000
    CASH_P2PKH = 0x00
    CASH_P2SH = 0x08 >> 3
    
    FEE_RATE = 1 # in sat per byte (sat/B)
    DUST_THRESHOLD = 546 * FEE_RATE
    
    BLOCKHEADER_SIZE = 80 # 80 bytes
    
    # Signature hash types and flags
    SIGHASH_ALL = 0x01
    SIGHASH_NONE = 0x02
    SIGHASH_SINGLE = 0x03
    SIGHASH_FORKID = 0x40
    SIGHASH_ANYONECANPAY = 0x80
    
    # Services flags
    NODE_NONE = 0
    NODE_NETWORK = (1 << 0)
    NODE_GETUTXO = (1 << 1)
    NODE_BLOOM = (1 << 2)
    NODE_XTHIN = (1 << 4)
    NODE_BITCOIN_CASH = (1 << 5)
    
    # Inventory Vectors
    MSG_ERROR = 0
    MSG_TX    = 1
    MSG_BLOCK = 2
    MSG_FILTERED_BLOCK = 3  # Defined in BIP-37
    MSG_CMPCT_BLOCK = 4     # Defined in BIP-152
    
    # Rejection codes
    REJECT_MALFORMED = 0x01
    REJECT_INVALID = 0x02
    REJECT_OBSOLETE = 0x11
    REJECT_DUPLICATE = 0x12
    REJECT_NONSTANDARD = 0x40
    REJECT_DUST = 0x41
    REJECT_INSUFFICIENTFEE = 0x42
    REJECT_CHECKPOINT = 0x43
    
    @classmethod
    def set_mainnet(self):
        ''' Main network. '''
        self.testnet = False
        
        self.WIF_PREFIX = 0x80
        self.LEGACY_P2PKH = 0x00
        self.LEGACY_P2SH = 0x05
        self.CASH_HRP = "bitcoincash"
        
        self.XPRV_HEADER = 0x0488ade4
        self.XPUB_HEADER = 0x0488b21e
        
        self.BIP44_TYPE = 0x91
        
        self.NETWORK_MAGIC = 0xe8f3e1e3
        self.DEFAULT_PORT = 8333
        
        # Genesis Block
        self.GENESIS_BLOCK_ID = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        self.GENESIS_BLOCK_VERSION = 1
        self.GENESIS_MERKLE_ROOT = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        self.GENESIS_BLOCK_TIMESTAMP = 1231006505
        self.GENESIS_BLOCK_BITS = 0x1d00ffff
        self.GENESIS_BLOCK_NONCE = 2083236893
    
    @classmethod
    def set_testnet(self):
        ''' Test network. '''
        self.testnet = True
        
        self.WIF_PREFIX = 0xef
        self.LEGACY_P2PKH = 0x6f
        self.LEGACY_P2SH = 0xc4
        self.CASH_HRP = "bchtest"
        
        self.XPRV_HEADER = 0x043587cf
        self.XPUB_HEADER = 0x04358394
        
        self.BIP44_TYPE = 0x01
        
        self.NETWORK_MAGIC = 0xf4f3e5f4
        self.DEFAULT_PORT = 18333
        
Constants.set_mainnet()
#Constants.set_testnet()