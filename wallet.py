#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (PublicKey, seed_from_mnemonic, root_from_seed, decode_xkey, 
                    xpub_from_xprv, private_derivation, public_derivation)
from address import Address
from constants import *
from mnemonic import generate_mnemonic

def get_account( mxprv, i ):
    ''' Returns extended keys (private and public) of the account i (BIP-44).'''
    coin_type = Constants.BIP44_TYPE
    branch = "m"
    sequence = "m/44'/{:d}'/{:d}'".format(coin_type, i)
    return private_derivation(mxprv, branch, sequence)

def get_adresses_from_account( account_xpub, is_internal=False, addr_index=range(0,20) ):
    if isinstance(addr_index, int):
        addr_index = [addr_index]
    branch_number = 1 if is_internal else 0
    branch_xpub = public_derivation( account_xpub, "", "/{:d}".format(branch_number) )
    addresses = []
    for i in addr_index:
        xpub = public_derivation( branch_xpub, "", "/{:d}".format(i) )
        pubkey, _, _, _, _ = decode_xkey( xpub )
        addresses.append( Address.from_pubkey( pubkey ).to_cash() )
    return addresses

class KeyStoreError(Exception):
    '''Exception used for KeyStore errors.'''
    
class KeyStore:
    
    def __init__(self):
        self.keypair = None
    
    def get_type(self):
        return None
        
    def dump(self):
        return {'keypair': self.keypair}
        
    def is_watching_only(self):
        return False
    
    def __repr__(self):
        return "<KeyStore>"
    
class ImportedKeyStore(KeyStore):
    ''' Imported single-key storage. '''
    
    def __init__(self, keypair):
        self.keypair = keypair
        
    def get_type(self):
        return 'imported'
    
    @classmethod
    def from_wifkey(self, wifkey):
        keypair = (wifkey , PublicKey.from_prvkey( wifkey, True ).to_ser(strtype=True) )
        return self( keypair )
    
    @classmethod
    def from_pubkeys(self, pubkey):
        if isinstance(pubkey, bytes):
            pubkey = pubkey.hex()
        return ( (None, pubkey) )
    
    def is_watching_only(self):
        return bool( self.keypair[0] )
    

class DeterministicKeyStore(KeyStore):
    ''' Deterministic single-account key storage. '''
    
    def __init__(self, account, mnemonic="", passphrase="" ):
        self.keypair = account
        self.mnemonic = mnemonic
        self.passphrase = passphrase
        
    def get_type(self):
        return 'deterministic'
    
    @classmethod
    def from_mnemonic(self, mnemonic, passphrase=""):
        seed = seed_from_mnemonic( mnemonic, passphrase )
        mxprv, _ = root_from_seed( seed )
        account = get_account( mxprv, 0 ) # first account
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
        d['keypair'] = self.keypair
        return d
    
    def get_account_xprv(self):
        return self.keypair[0]
    
    def get_account_xpub(self):
        return self.keypair[1]
    
    def is_watching_only(self):
        return bool( self.keypair[0] )
    
    

class Wallet:
    ''' Single keystore wallet. '''
    
    # synchronizer ?
    
    def __init__(self, keystore=KeyStore(), addresses={"external": [], "internal": []}, utxos=[]):
        self.addresses = addresses
        self.history = {}
        self.keystore = keystore
        self.transactions = {}
        self.utxos = utxos
        
        # No encryption for the moment
        self.encrypted = False
    
    @classmethod
    def from_mnemonic(self, mnemonic):
        keystore = DeterministicKeyStore.from_mnemonic( mnemonic )
        addresses = {}
        addresses['external'] = get_adresses_from_account( keystore.get_account_xpub(), False, range(0,20) )
        addresses['internal'] = get_adresses_from_account( keystore.get_account_xpub(), True, range(0,5) )
        
        utxos = [ {'txid':None, 'index':0, 'value':10000, 'address':addresses['external'][0]} ]
        return self( keystore, addresses, utxos )
    
    @classmethod    
    def new(self):
        return self.from_mnemonic( generate_mnemonic( 128 ) )
        
    def synchronize(self):
        
    
        