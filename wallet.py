#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (PublicKey, seed_from_mnemonic, root_from_seed, xpub_from_xprv, private_derivation)
from constants import bch_mainnet
from mnemonic import generate_mnemonic

def get_account( mxprv, i ):
    ''' Returns extended keys (private and public) of the account i (BIP-44).'''
    coin_type = bch_mainnet.BIP44_TYPE
    branch = "m"
    sequence = "m/44'/{:d}'/{:d}'".format(coin_type, i)
    return private_derivation(mxprv, branch, sequence)

class KeyStoreError(Exception):
    '''Exception used for KeyStore errors.'''
    
class ImportedKeyStore:
    ''' Imported single-key storage. '''
    
    def __init__(self, keypairs):
        self.keypairs = keypairs
    
    @classmethod
    def from_wifkey(self, wifkey):
        self.keypair = (wifkey , PublicKey.from_prvkey( wifkey, True ) )
    
    @classmethod
    def from_pubkeys(self, pubkey):
        if isinstance(pubkey, bytes):
            pubkey = pubkey.hex()
        self.keypair = (None, pubkey)
                        
    def is_watching_only(self):
        return bool( self.keypair[0] )

class DeterministicKeyStore:
    ''' Deterministic single-account key storage. '''
    
    def __init__(self, account, mnemonic="", passphrase="" ):
        self.account = account
        self.mnemonic = mnemonic
        self.passphrase = passphrase
    
    @classmethod
    def from_mnemonic(self, mnemonic, passphrase=""):
        seed = seed_from_mnemonic( mnemonic, passphrase )
        mxprv, _ = root_from_seed( seed )
        account = get_account( mxprv, 0 )
        return self( account, mnemonic, passphrase )
    
    @classmethod
    def from_account_xprv(self, xprv):
        return self( (xprv, xpub_from_xprv(xpub)) )
    
    @classmethod
    def from_account_xpub(self, xpub):
        return self( ("", xpub) )

    def dump(self):
        d = {}
        if self.mnemonic:
            d['mnemonic'] = self.mnemonic
            if self.passphrase:
                d['passphrase'] = self.passphrase
        d['account'] = self.account
        return d
    
    def get_account_xprv(self):
        return self.account[0]
    
    def get_account_xpub(self):
        return self.account[1]
    
    def is_watching_only(self):
        return bool( self.account[0] )

class Wallet:
    
    def __init__(self, keystores=[]):
        self.addresses = {"external": [], "internal": []}
        self.history = {}
        self.keystores = keystores
        self.transactions = {}
        
        # No encryption for the moment
        self.encrypted = False
        
    @classmethod    
    def new(self):
        mnemonic = generate_mnemonic( 128 )
        keystore = DeterministicKeyStore.from_mnemonic( mnemonic )
        return self( [keystore] )