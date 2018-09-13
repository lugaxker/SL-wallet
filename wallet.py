#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import collections
import json

from crypto import (PublicKey, PrivateKey, seed_from_mnemonic, root_from_seed, decode_xkey, 
                    xpub_from_xprv, private_derivation, public_derivation)
from address import Address
from mnemonic import generate_mnemonic
from blockexplorer import get_address_utxos

from transaction import Transaction
from network import Network

from constants import *

def get_account( mxprv, i ):
    ''' Returns extended keys (private and public) of the account i (BIP-44).'''
    coin_type = Constants.BIP44_TYPE
    branch = "m"
    sequence = "m/44'/{:d}'/{:d}'".format(coin_type, i)
    return private_derivation(mxprv, branch, sequence)

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
    
    def get_mnemonic(self):
        if not self.mnemonic:
            raise KeyStoreError("no mnemonic phrase stored")
        return self.mnemonic
    
    def get_prvkeys(self, branch, index):
        ''' branch (int): external (0) or internal (1) '''
        assert branch in (0,1)
        if self.is_watching_only():
            raise KeyStoreError("watching-only keystore")
        if isinstance(index, int):
            index = [index]
        branch_xprv, _ = private_derivation( self.get_account_xprv(), "", "/{:d}".format(branch) )
        prvkeys = []
        for i in index:
            xprv, _ = private_derivation( branch_xprv, "", "/{:d}".format(i) )
            prvkey, _, _, _, _ = decode_xkey( xprv )
            prvkeys.append( PrivateKey.from_hex( prvkey ) )
        return prvkeys
    
    def get_pubkeys(self, branch, index ):
        ''' branch (int): external (0) or internal (1) '''
        assert branch in (0,1)
        if isinstance(index, int):
            index = [index]
        branch_xpub = public_derivation( self.get_account_xpub(), "", "/{:d}".format(branch) )
        pubkeys = []
        for i in index:
            xpub = public_derivation( branch_xpub, "", "/{:d}".format(i) )
            pubkey, _, _, _, _ = decode_xkey( xpub )
            pubkeys.append( PublicKey.from_ser( pubkey ) )
        return pubkeys
        
    def get_addresses(self, branch, index):
        assert branch in (0,1)
        if isinstance(index, int):
            index = [index]
        branch_xpub = public_derivation( self.get_account_xpub(), "", "/{:d}".format(branch) )
        addresses = []
        for i in index:
            xpub = public_derivation( branch_xpub, "", "/{:d}".format(i) )
            pubkey, _, _, _, _ = decode_xkey( xpub )
            addresses.append( Address.from_pubkey( pubkey ) )
        return addresses

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
        return not bool( self.keypair[0] )
    

class WalletError(Exception):
    '''Exception used for KeyStore errors.'''
    pass

class Wallet:
    ''' Single keystore wallet. '''
    
    def __init__(self, keystore=KeyStore(), recv_addresses=[], chng_addresses=[], utxos=[], transactions = [], block_height=0):
        self.keystore = keystore
        self.recv_addresses = recv_addresses
        self.chng_addresses = chng_addresses
        self.utxos = utxos
        self.transactions = transactions
        self.history = {}
        self.network = Network()
        
        # No encryption for the moment
        self.encrypted = False
    
    @classmethod
    def from_mnemonic(self, mnemonic):
        keystore = DeterministicKeyStore.from_mnemonic( mnemonic )        
        recv_addresses = keystore.get_addresses(0, 0)
        chng_addresses = []
        return self( keystore, recv_addresses, chng_addresses )
    
    @classmethod    
    def new(self):
        return self.from_mnemonic( generate_mnemonic( 128 ) )
    
    @classmethod
    def load(self, filename="wallet.json"):
        with open(filename, 'r') as f:
            winfo = json.load(f)
    
        try:
            ksinfo = winfo['keystore']
            mnemonic = ksinfo['mnemonic']
            passphrase = ksinfo['passphrase']
            account = tuple( ksinfo['keypair'] )
            keystore = DeterministicKeyStore(account, mnemonic, passphrase)
            recv_addresses = [ Address.from_string( a ) for a in winfo['addresses']['receiving'] ]
            chng_addresses = [ Address.from_string( a ) for a in winfo['addresses']['change'] ]
            utxos = [{'txid':o['txid'], 'index':o['index'], 'value':o['value'], 
                      'address': Address.from_string( o['address'] )} for o in winfo['utxos']]
            transactions = [ {'txid': bytes.fromhex( tx['txid'] ), 'raw': bytes.fromhex( tx['raw']), 'sent': tx['sent'] } for tx in winfo['transactions'] ]
            block_height = winfo['block_height']
            
            print("wallet loaded")
            
        except:
            raise WalletError('cannot load wallet')
        
        return self( keystore, recv_addresses, chng_addresses, utxos, transactions, block_height )
    
    def save(self, filename="wallet.json" ):
        ''' Save wallet into a json file.
        mnemonic: mnemonic phrase
        keypair(s): account(s)
        addresses: {"receiving": [addresses], "change": [addresses]} (cash without hrp)
        utxos: [{'txid': hex, 'index': int, 'value': int, 'address': str}]
        transactions: [{'txid', 'rawtx'}] '''    
        ksinfo = {}
        ksinfo['mnemonic'] = self.keystore.mnemonic
        ksinfo['passphrase'] = self.keystore.passphrase
        ksinfo['keypair'] = self.keystore.keypair

        addrinfo = {}
        addrinfo['receiving'] = [ a.to_cash() for a in self.recv_addresses ]
        addrinfo['change'] = [ a.to_cash() for a in self.chng_addresses ]
        
        winfo = {}
        winfo['keystore'] = ksinfo
        winfo['addresses'] = addrinfo
        utxos = self.utxos
        winfo['utxos'] = [ {'txid':o['txid'], 'index':o['index'], 'value':o['value'], 'address':o['address'].to_cash()} for o in self.utxos ]
        winfo['transactions'] = [ {'txid': tx['txid'].hex(), 'raw': tx['raw'].hex(), 'sent': tx['sent'] } for tx in self.transactions]
        
        winfo['block_height'] = self.network.block_height
        
        with open(filename, 'w') as f:
            json.dump(winfo, f, ensure_ascii=False)
            
        print("wallet saved")
    
    def add_new_address(self, branch):
        ''' branch: external/receiving (0) or internal/change (1)'''
        assert branch in (0,1)
        if branch == 0:
            self.recv_addresses += self.keystore.get_addresses( branch, len(self.recv_addresses) )
        else:
            self.chng_addresses += self.keystore.get_addresses( branch, len(self.chng_addresses) )
    
    def update_utxos(self):
        print( "update utxos")
        utxos = []
        for a in (self.recv_addresses + self.chng_addresses):
            utxos += get_address_utxos(a) 
        self.utxos = utxos
        
    def start_network(self):
        ''' Starts to interact with the network '''
        self.network.start()
    
    def stop_network(self):
        self.network.shutdown()
    
    def make_standard_transaction(self, output_address, amount):
        tx_version = 1
        assert isinstance(output_address, Address)
        assert amount >= Constants.DUST_THRESHOLD
        
        tx = Transaction( tx_version, [], [ {'address': output_address, 'value': amount } ], self.network.block_height )
        is_possible = False
        prvkeys = []
        unlocked_funds = 0
        for utxo in self.utxos:
            unlocked_funds += utxo['value']
            
            address = None
            for i, a in enumerate(self.recv_addresses):
                if a == utxo['address']:
                    address = a
                    branch = 0
                    index = i
                    break
            for i, a in enumerate(self.chng_addresses):
                if a == utxo['address']:
                    address = a
                    branch = 1
                    index = i
                    break
            if not address:
                raise WalletError("UTXO address cannot be found")
            
            pubkeys = self.keystore.get_pubkeys( branch, index )
            prvkeys.extend( self.keystore.get_prvkeys( branch, index ) )
            
            tx.add_input( { 'txid': utxo['txid'], 'index': utxo['index'], 'value': utxo['value'], 'address': address, 'pubkeys': pubkeys, 'nsigs': 1, 'sequence': Constants.SEQUENCE_NUMBER } )
            
            txsize = tx.estimate_size()
            fee = Constants.FEE_RATE * txsize
            r = unlocked_funds - amount - fee
            if r == 0:
                # no need for change address
                is_possible = True
                break
            
            txsize += 32 + 2 * (output_address.kind == Constants.CASH_P2PKH)
            fee = Constants.FEE_RATE * txsize
            r = unlocked_funds - amount - fee
            
            if r >= Constants.DUST_THRESHOLD:
                self.add_new_address( branch=1 )
                tx.add_output( {'address': self.chng_addresses[-1], 
                             'value': unlocked_funds - amount - fee} )
                is_possible = True
                break
            
        if not is_possible:
            raise WalletError("cannot create transaction")
            
        tx.sign( prvkeys )
        rawtx = tx.serialize()
        txid = tx.txid()
        
        fee = tx.get_fee()
        
        return rawtx, txid, fee
    
    def add_new_transaction(self, raw, txid):
        tx = {'txid': txid, 'raw': raw, 'sent': True}
        if tx not in self.transactions:
            self.transactions.append( tx )
        
    def compute_max_amount(self):
        ''' For P2PKH inputs and compressed public keys only. '''
        balance = self.get_balance()
        ninputs = len(self.utxos)
        assert ninputs < 0xfd
        noutputs = 1
        txsize = 10 + ninputs*148 + noutputs*34
        fee = Constants.FEE_RATE * txsize
        amount = balance - fee
        if amount < Constants.DUST_THRESHOLD:
            raise WalletError("amount must be higher than dust threshold")
        return amount
    
    def get_address_balance(self, addr):
        val = 0
        for utxo in self.utxos:
            if utxo['address'] == addr:
                val += utxo['value']
        return val
        
    def get_balance(self):
        return sum( utxo['value'] for utxo in self.utxos )
        
        