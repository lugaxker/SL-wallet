#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (dsha256, EllipticCurveKey)
from address import *
from script import *

SEQUENCE_NUMBER = SEQUENCE_NUMBER = 0xffffffff - 1
BCH_SIGHASH_TYPE = 0x41

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
        
    @classmethod
    def minimal_transaction(self, input_address, output_address, amount, prevout_txid, prevout_index, prevout_value, locktime):
        ''' Minimal transaction. '''
        txin = {}
        txout = {}

        # Input address
        txin['address'] = Address.from_string( input_address )
        
        txin['prevout_txid'] = prevout_txid
        txin['prevout_index'] = prevout_index
        txin['prevout_value'] = prevout_value
        
        txin['sequence'] = SEQUENCE_NUMBER
        txin['type'] = 0
        
        # Output address
        txout['type'] = 0
        txout['address'] = Address.from_string( output_address )
        txout['value'] = amount
        
        return self(txin, txout, locktime)
    
    def serialize_outpoint(self):
        txin = self._input
        return (bytes.fromhex( txin['prevout_txid'] )[::-1] +
                txin['prevout_index'].to_bytes(4,'little') )
    
    def serialize_input(self):
        txin = self._input
        outpoint  = self.serialize_outpoint()
        publicKey = bytes.fromhex(txin['pubkey'])
        signature = bytes.fromhex(txin['signature'])
        unlockingScript = unlocking_script( publicKey, signature )
        lengthUnlockingScript = var_int( len( unlockingScript ) )
        nSequence = txin['sequence'].to_bytes(4,'little')
        return outpoint + lengthUnlockingScript + unlockingScript + nSequence
    
    def serialize_output(self):
        txout = self._output
        nAmount = txout['value'].to_bytes(8,'little')
        lockingScript = locking_script_from_address( txout['address'] )
        lengthLockingScript = var_int( len(lockingScript) )
        return nAmount + lengthLockingScript + lockingScript
        
    def serialize_preimage(self):
        nVersion = self.version.to_bytes(4,'little')
        nLocktime = self.locktime.to_bytes(4,'little')
        nHashtype = self.hashtype.to_bytes(4,'little') # signature hashtype (little-endian)
        
        nSequence = self._input['sequence'].to_bytes(4,'little')
        nAmount = self._output['value'].to_bytes(8,'little')
        try:
            prevValue = self._input['prevout_value'].to_bytes(8,'little')
        except KeyError:
            raise TransactionError("previous output value missing")
        
        outpoint = self.serialize_outpoint()
        hashPrevouts = dsha256( outpoint )
        hashSequence = dsha256( nSequence )
        
        prevLockingScript = locking_script_from_address( self._input['address'] )
        lengthPrevLockingScript = var_int( len(prevLockingScript) )
        
        lockingScript = locking_script_from_address( self._output['address'] )
        lengthLockingScript = var_int( len(lockingScript) )
        
        hashOutputs = dsha256( nAmount + lengthLockingScript + lockingScript )       
        
        return (nVersion + hashPrevouts + hashSequence + outpoint + 
                lengthPrevLockingScript + prevLockingScript + prevValue +
                nSequence + hashOutputs + nLocktime + nHashtype)
    
    def serialize(self):
        ''' Serializes the transaction. '''
        nVersion = self.version.to_bytes(4,'little') # version (little-endian)
        nLocktime = self.locktime.to_bytes(4,'little') # lock time (little-endian)
        txins = var_int(1) + self.serialize_input() # transaction inputs
        txouts = var_int(1) + self.serialize_output() # transaction outputs
        return nVersion + txins + txouts + nLocktime
    
    def txid(self):
        '''Returns transaction identifier.'''
        raw = self.serialize()
        return dsha256( raw )[::-1]
    
    def sign(self, eckey):
        '''Signs the transaction. 
        eckey (EllipticCurveKey) : pair of elliptic curve keys
        signature (bytes) : DER-encoded signature of the double sha256 of the
                            preimage, plus signature hashtype
        publicKey (bytes) : serialized public key'''
        txin = self._input
        prehash = dsha256( self.serialize_preimage() )
        signature = eckey.sign( prehash ) + bytes( [self.hashtype & 0xff] )
        publicKey = eckey.serialize_pubkey()
        txin['pubkey'] = publicKey.hex()
        txin['signature'] = signature.hex()