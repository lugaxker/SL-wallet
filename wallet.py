#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import collections

from crypto import (PublicKey, PrivateKey, seed_from_mnemonic, root_from_seed, decode_xkey, 
                    xpub_from_xprv, private_derivation, public_derivation)
from address import Address
from mnemonic import generate_mnemonic
from blockexplorer import get_address_utxos

from transaction import Transaction

from constants import *

def get_account( mxprv, i ):
    ''' Returns extended keys (private and public) of the account i (BIP-44).'''
    coin_type = Constants.BIP44_TYPE
    branch = "m"
    sequence = "m/44'/{:d}'/{:d}'".format(coin_type, i)
    return private_derivation(mxprv, branch, sequence)

def get_adresses_from_account( account_xpub, internal, index):
    if isinstance(index, int):
        index = [index]
    branch_number = 1 if internal else 0
    branch_xpub = public_derivation( account_xpub, "", "/{:d}".format(branch_number) )
    addresses = []
    for i in index:
        xpub = public_derivation( branch_xpub, "", "/{:d}".format(i) )
        pubkey, _, _, _, _ = decode_xkey( xpub )
        addresses.append( ( Address.from_pubkey( pubkey ).to_cash(), branch_number, i ) )
    return addresses

def get_pubkeys_from_account( account_xpub, internal, index ):
    if isinstance(index, int):
        index = [index]
    branch_number = 1 if internal else 0
    branch_xpub = public_derivation( account_xpub, "", "/{:d}".format(branch_number) )
    pubkeys = []
    for i in index:
        xpub = public_derivation( branch_xpub, "", "/{:d}".format(i) )
        pubkey, _, _, _, _ = decode_xkey( xpub )
        pubkeys.append( pubkey.hex() )
    return pubkeys

def get_prvkeys_from_account( account_xprv, internal, index):
    if isinstance(index, int):
        index = [index]
    branch_number = 1 if internal else 0
    branch_xprv, _ = private_derivation( account_xprv, "", "/{:d}".format(branch_number) )
    prvkeys = []
    for i in index:
        xprv, _ = private_derivation( branch_xprv, "", "/{:d}".format(i) )
        prvkey, _, _, _, _ = decode_xkey( xprv )
        prvkeys.append( PrivateKey.from_hex( prvkey ) )
    return prvkeys

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
    
class WalletError(Exception):
    '''Exception used for KeyStore errors.'''    

class Wallet:
    ''' Single keystore wallet. '''
    
    def __init__(self, keystore=KeyStore(), addresses=[]):
        self.addresses = addresses
        self.history = {}
        self.keystore = keystore
        self.transactions = {}
        self.block_height = 0
        
        # No encryption for the moment
        self.encrypted = False
    
    @classmethod
    def from_mnemonic(self, mnemonic):
        keystore = DeterministicKeyStore.from_mnemonic( mnemonic )
        account_xpub = keystore.get_account_xpub()
        addresses = get_adresses_from_account( keystore.get_account_xpub(), False, 0 )
        return self( keystore, addresses )
    
    @classmethod    
    def new(self):
        return self.from_mnemonic( generate_mnemonic( 128 ) )
    
    def add_new_address(self, internal=False):
        i = -1
        for addr in self.addresses:
            if bool(addr[1]) == internal:
                if addr[2] > i:
                    i = addr[2]
        self.addresses += get_adresses_from_account( self.keystore.get_account_xpub(), internal, i+1 )
    
    def update_utxos(self):
        utxos = []
        for addr in self.addresses:
            utxos += get_address_utxos(addr[0]) 
        self.utxos = utxos
        
    def synchronize(self):
        ''' Synchronizes with the network? '''
        pass
    
    def make_standard_transaction(self, address, amount):
        assert isinstance(address, str)
        
        inputs = []
        prvkeys = []
        unlocked_funds = 0
        for utxo in self.utxos:
            if unlocked_funds >= amount + 2*Constants.DUST_THRESHOLD:
                break
            unlocked_funds += utxo['value']
            for a in self.addresses:
                if utxo['address'] == a[0]:
                    addr = a
            pubkeys = get_pubkeys_from_account( self.keystore.get_account_xpub(), addr[1], addr[2] )
            prvkeys.extend( get_prvkeys_from_account( self.keystore.get_account_xprv(), addr[1], addr[2] ) )
            inputs.append( { 'txid': utxo['txid'], 'index': utxo['index'], 'value': utxo['value'], 'address': Address.from_string( addr[0] ), 'pubkeys': pubkeys, 'nsigs': 1, 'sequence': Constants.SEQUENCE_NUMBER } )
            
        
        outputs = [ {'address': Address.from_string( address ), 'value': amount } ]
        
        tx = Transaction( inputs, outputs, locktime=0)
        txsize = ( tx.estimate_size() + 32 
                 + 2 * (Address.from_string( address ).kind == Constants.CASH_P2PKH) )
        fee = Constants.FEE_RATE * txsize
        
        r = unlocked_funds - amount - fee
        if r >= Constants.DUST_THRESHOLD:
            self.add_new_address(internal=True)
            tx.add_output( {'address': Address.from_string( self.addresses[-1][0] ), 
                             'value': unlocked_funds - amount - fee} )
        else:
            fee = Constants.FEE_RATE * tx.estimate_size()
            if unlocked_funds - amount != fee:
                raise WalletError('cannot create transcation')
            
        tx.sign( prvkeys )
        rawtx = tx.serialize()
        txid = tx.txid()
        
        return rawtx, txid
        
    def max_transaction(self, address):
        inputs = []
        prvkeys = []
        balance = 0
        for utxo in self.utxos:
            balance += utxo['value']
            for a in self.addresses:
                if utxo['address'] == a[0]:
                    addr = a
            pubkeys = get_pubkeys_from_account( self.keystore.get_account_xpub(), addr[1], addr[2] )
            prvkeys.extend( get_prvkeys_from_account( self.keystore.get_account_xprv(), addr[1], addr[2] ) )
            inputs.append( { 'txid': utxo['txid'], 'index': utxo['index'], 'value': utxo['value'], 'address': Address.from_string( addr[0] ), 'pubkeys': pubkeys, 'nsigs': 1, 'sequence': Constants.SEQUENCE_NUMBER } )
        
        tx = Transaction( inputs, [] )
        txsize = tx.estimate_size() + 34
        amount = balance - Constants.FEE_RATE * txsize
        tx.add_output( {'address': Address.from_string( address ), 'value': amount } )
        assert( amount >= Constants.DUST_THRESHOLD )
        
        tx.sign( prvkeys )
        rawtx = tx.serialize()
        txid = tx.txid()
        
        return rawtx, txid
    
    #def make_unsigned_transaction(self, inputs, outputs):
        #if self.get_balance()
        
        #tx = Transaction( inputs, outputs )
        #return tx
    
    #def sign_transaction(self, tx):
        #pass
    
    #def make_transaction(self, prvkeys):
        #tx = self.make_unsigned_transaction(inputs, outputs)
        #self.sign_transaction(tx)
        #tx.compute_fee()
    
        ## Signing
        #tx.sign([[prvkey]])
        #return tx
    
    
    def get_address_balance(self, addr):
        val = 0
        for utxo in self.utxos:
            if utxo['address'] == addr:
                val += utxo['value']
        return val
        
    def get_balance(self):
        return sum( utxo['value'] for utxo in self.utxos )
        
        