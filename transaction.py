#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (dsha256, EllipticCurveKey)
from address import *
from script import *

SEQUENCE_NUMBER = 0xffffffff - 1
BCH_SIGHASH_TYPE = 0x41

FEE_RATE = 2 # in satoshis per byte (sat/B)

def var_int(i):
    '''Returns variable length integer used in the transaction payload.'''
    if i < 0xfd:
        return bytes([i])
    elif i <= 0xffff:
        return bytes([0xfd]) + i.to_bytes(2, 'little')
    elif i <= 0xffffffff:
        return bytes([0xfe]) + i.to_bytes(4, 'little')
    elif i <= 0xffffffffffffffff:
        return bytes([0xff]) + i.to_bytes(8, 'little')
    else:
        raise ValueError("Integer is too big")

class TransactionError(Exception):
    '''Exception used for Transaction errors.'''

class Transaction:
    ''' Transaction. '''
    
    def __init__(self, txin = None, txout = None, locktime = 0):
        self._input = txin
        self._output = txout
        self.version = 1 # version 2 transactions exist
        self.locktime = locktime
        self.hashtype = BCH_SIGHASH_TYPE # hardcoded signature hashtype
        
        self.iscomplete = False
        
    @classmethod
    def minimal_transaction(self, input_address, output_address, prevout_txid, prevout_index, prevout_value, locktime):
        ''' Minimal transaction: one-input-one-output transaction. '''
        txin = {}
        txout = {}

        # Input address
        txin['address'] = Address.from_string( input_address )
        txin['sequence'] = SEQUENCE_NUMBER
        
        txin['txid'] = prevout_txid
        txin['index'] = prevout_index
        txin['value'] = prevout_value

        # Output address
        txout['address'] = Address.from_string( output_address )
        txout['value'] = 0 # 
        
        return self(txin, txout, locktime)
    
    def get_preimage_script(self):
        txin = self._input
        if txin['address'].kind == Address.ADDR_P2PKH:
            return locking_script( txin['address'] )
        elif txin['address'].kind == Address.ADDR_P2SH:
            m = txin['nsigs']
            pubkeys = [bytes.fromhex(pk) for pk in txin['pubkeys']]
            return multisig_locking_script( pubkeys, m )
        return None
    
    def serialize_outpoint(self):
        ''' Seraializes the outpoint of the input (prev. txid + prev. index).'''        
        txin = self._input
        return (bytes.fromhex( txin['txid'] )[::-1] +
                txin['index'].to_bytes(4,'little') )
    
    def serialize_input(self):
        txin = self._input
        outpoint  = self.serialize_outpoint()
        pubkeys = [bytes.fromhex(pk) for pk in txin['pubkeys']]
        signatures = [bytes.fromhex(sig) for sig in txin['signatures']]
        unlockingScript = unlocking_script(txin['address'], pubkeys, signatures)
        unlockingScriptSize = var_int( len( unlockingScript ) )
        nSequence = txin['sequence'].to_bytes(4,'little')
        return outpoint + unlockingScriptSize + unlockingScript + nSequence
    
    def serialize_output(self):
        txout = self._output
        nAmount = txout['value'].to_bytes(8,'little')
        lockingScript = locking_script( txout['address'] )
        lockingScriptSize = var_int( len(lockingScript) )
        return nAmount + lockingScriptSize + lockingScript
        
    def serialize_preimage(self):
        ''' Serializes the preimage of the transaction (BIP-143).'''
        nVersion = self.version.to_bytes(4,'little')
        nLocktime = self.locktime.to_bytes(4,'little')
        nHashtype = self.hashtype.to_bytes(4,'little') # signature hashtype (little-endian)
        
        txin = self._input
        txout = self._output
        
        nSequence = txin['sequence'].to_bytes(4,'little')
        nAmount = txout['value'].to_bytes(8,'little')
        try:
            prevValue = txin['value'].to_bytes(8,'little')
        except KeyError:
            raise TransactionError("previous output value missing")
        
        outpoint = self.serialize_outpoint()
        hashPrevouts = dsha256( outpoint )
        hashSequence = dsha256( nSequence )
        
        input_addr = txin['address']
        if input_addr.kind == Address.ADDR_P2PKH:
            prevLockingScript = locking_script( input_addr )
        elif input_addr.kind == Address.ADDR_P2SH:
            pubkeys = [bytes.fromhex(pk) for pk in txin['pubkeys']]
            prevLockingScript = multisig_locking_script( pubkeys, txin['nsigs'])
        else:
            raise TransactionError("wrong type of address")
        
        prevLockingScriptSize = var_int( len(prevLockingScript) )
        
        lockingScript = locking_script( txout['address'] )
        lockingScriptSize = var_int( len(lockingScript) )
        
        hashOutputs = dsha256( nAmount + lockingScriptSize + lockingScript )       
        
        return (nVersion + hashPrevouts + hashSequence + outpoint + 
                prevLockingScriptSize + prevLockingScript + prevValue +
                nSequence + hashOutputs + nLocktime + nHashtype)
    
    def serialize(self):
        ''' Serializes the transaction. '''
        nVersion = self.version.to_bytes(4,'little') # version (little-endian)
        nLocktime = self.locktime.to_bytes(4,'little') # lock time (little-endian)
        txins = var_int(1) + self.serialize_input() # transaction inputs
        txouts = var_int(1) + self.serialize_output() # transaction outputs
        self.raw = nVersion + txins + txouts + nLocktime
        self.iscomplete = True
        
    def txid(self):
        '''Returns transaction identifier.'''
        if not self.iscomplete:
            return None
        return dsha256( self.raw )[::-1]
    
    def sign(self, eckey):
        '''Signs the transaction. 
        eckey (EllipticCurveKey) : pair of elliptic curve keys
        signature (bytes) : DER-encoded signature of the double sha256 of the
                            preimage, plus signature hashtype
        publicKey (bytes) : serialized public key'''
        print("PREIMAGE")
        print( self.serialize_preimage().hex() )
        prehash = dsha256( self.serialize_preimage() )
        signature = eckey.sign( prehash ) + bytes( [self.hashtype & 0xff] )
        publicKey = eckey.serialize_pubkey()
        self._input['pubkeys'] = [ publicKey.hex() ]
        self._input['signatures'] = [ signature.hex() ]
    
    def sign_multisig(self, eckeys, pubkeys, nsigs):
        ''' Signs a multisig transaction.
        eckeys: list of pairs of elliptic curve keys
        pubkeys: sorted list of public keys involved in the multisig address
        nsigs: number of signatures required to unlock the multisig address '''
        assert(len(eckeys) == nsigs)
        
        # Public keys
        self._input['pubkeys'] = [pk.hex() for pk in pubkeys]
        self._input['nsigs'] = nsigs
        
        # Sorting of keys
        sorted_eckeys = []
        for eckey in eckeys:
            pubkey = eckey.serialize_pubkey()
            assert(pubkey in pubkeys)
            sorted_eckeys += [(pubkeys.index(pubkey), eckey)]
        sorted_eckeys.sort(key = lambda x: x[0])
        eckeys = [k[1] for k in sorted_eckeys]
        
        # Signatures        
        prehash = dsha256( self.serialize_preimage() )
        signatures = [ eckey.sign( prehash ) + bytes( [self.hashtype & 0xff] ) for eckey in eckeys ]
        self._input['signatures'] = [sig.hex() for sig in signatures]
        
        
    
    def estimate_size(self):
        if not self.iscomplete:
            return None
        return len(self.raw)
    
    def compute_fee(self):
        if self.iscomplete:
            self._input['value']
            self._output['value'] = self._input['value'] - self.estimate_size() * FEE_RATE
            self.iscomplete = False
            
    def input_value(self):
        return self._input['value']

    def output_value(self):
        return self._output['value']

    def get_fee(self):
        return self.input_value() - self.output_value()