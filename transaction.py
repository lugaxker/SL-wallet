#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (dsha256, PrivateKey, PublicKey)
from address import *
from script import *

SEQUENCE_NUMBER = 0xffffffff - 1
BCH_SIGHASH_TYPE = 0x41

FEE_RATE = 1 # in satoshis per byte (sat/B)

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
    
def push_data_size(n):
    OP_PUSHDATA1 = 0x4c
    if n < OP_PUSHDATA1:
        return 1
    elif n <= 0xff:
        return 2
    elif n <= 0xffff:
        return 3
    elif n <= 0xffffffff:
        return 5
    else:
        raise ValueError("Data is too long")

def var_int_size(i):
    if i < 0xfd:
        return 1
    elif i <= 0xffff:
        return 3
    elif i <= 0xffffffff:
        return 5
    elif i <= 0xffffffffffffffff:
        return 9
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
    def minimal_transaction(self, pubkeys, nsigs, output_address, prevout_txid, prevout_index, prevout_value, locktime):
        ''' Minimal transaction: one-input-one-output transaction. '''
        txin = {}
        txout = {}

        # Input address
        if nsigs == 1:
            txin['address'] = Address.from_pubkey( bytes.fromhex( pubkeys[0] ) )
        else:
            redeem_script = multisig_locking_script( [bytes.fromhex(pk) for pk in pubkeys], nsigs)
            txin['address'] = Address.from_script( redeem_script )
        txin['sequence'] = SEQUENCE_NUMBER
        
        txin['txid'] = prevout_txid
        txin['index'] = prevout_index
        txin['value'] = prevout_value
        
        txin['pubkeys'] = pubkeys
        txin['nsigs'] = nsigs

        # Output address
        txout['address'] = Address.from_string( output_address )
        txout['value'] = 0 # 
        
        return self(txin, txout, locktime)
    
    def get_preimage_script(self):
        ''' Returns the previous locking script for a P2PKH address,
        and the redeem script for a P2SH address (only multisig for now). '''
        txin = self._input
        input_addr = txin['address']
        if input_addr.kind == Address.ADDR_P2PKH:
            return locking_script( input_addr )
        elif input_addr.kind == Address.ADDR_P2SH:
            pubkeys = [bytes.fromhex(pk) for pk in txin['pubkeys']]
            return multisig_locking_script( pubkeys, txin['nsigs'] )
        return None
    
    def serialize_outpoint(self):
        ''' Serializes the outpoint of the input (prev. txid + prev. index).'''        
        txin = self._input
        return (bytes.fromhex( txin['txid'] )[::-1] +
                txin['index'].to_bytes(4,'little') )
    
    def serialize_input(self):
        ''' Serializes an input: outpoint (previous output tx id + previous output index)
        + unlocking script (scriptSig) with its size + sequence number. '''
        txin = self._input
        outpoint  = self.serialize_outpoint()
        pubkeys = [bytes.fromhex(pk) for pk in txin['pubkeys']]
        signatures = [bytes.fromhex(sig) for sig in txin['signatures']]
        unlockingScript = unlocking_script(txin['address'], pubkeys, signatures)
        unlockingScriptSize = var_int( len( unlockingScript ) )
        nSequence = txin['sequence'].to_bytes(4,'little')
        return outpoint + unlockingScriptSize + unlockingScript + nSequence
    
    def serialize_output(self):
        ''' Serializes an output: value + locking script (scriptPubkey) with its size.'''
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

        prevLockingScript = self.get_preimage_script()
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
        
    def sign(self, prvkeys):
        '''Signs the transaction. 
        prvkeys (PrivateKey list)'''
        assert( len(prvkeys) == self._input['nsigs']) # Number of signatures required
        pubkeys = [bytes.fromhex(pk) for pk in self._input['pubkeys']] # Public keys
        if len(prvkeys) > 1: # Sorting of keys
            sorted_prvkeys = []
            for prvkey in prvkeys:
                pubkey = PublicKey.from_prvkey( prvkey ).to_ser()
                assert(pubkey in pubkeys)
                sorted_prvkeys += [(pubkeys.index(pubkey), prvkey)]
            sorted_prvkeys.sort(key = lambda x: x[0])
            prvkeys = [k[1] for k in sorted_prvkeys]
        prehash = dsha256( self.serialize_preimage() )
        hashtype = bytes( [self.hashtype & 0xff] ).hex()
        self._input['signatures'] = [ prvkey.sign( prehash, strtype=True ) + hashtype for prvkey in prvkeys ]
    
    def estimate_size(self):
        sz_version = 4
        sz_locktime = 4
        
        sz_prevout_txid = 32
        sz_prevout_index = 4
        if self._input['address'].kind == Address.ADDR_P2PKH:
            sz_sig = 0x48
            pubkey_prefix = int( self._input['pubkeys'][0][:2] )
            assert pubkey_prefix in (0x02, 0x03, 0x04) 
            if pubkey_prefix in (0x02, 0x03):
                sz_pubkey = 0x21
            else:
                sz_pubkey = 0x41
            sz_unlocking_script = (push_data_size(sz_sig) + sz_sig 
                                   + push_data_size(sz_pubkey) + sz_pubkey)
            
        elif self._input['address'].kind == Address.ADDR_P2SH:
            # only multisig for now
            sz_signatures = 1 + self._input['nsigs'] * (1 + 0x48)
            pubkey_prefixes = [int(pk[:2]) for pk in self._input['pubkeys']]
            sz_pubkeys = 0
            for prefix in pubkey_prefixes:
                assert prefix in (0x02, 0x03, 0x04)
                if prefix in (0x02, 0x03):
                    sz_pubkeys += 1 + 0x21
                else:
                    sz_pubkeys += 1 + 0x41
            sz_redeem_script = 1 + sz_pubkeys + 2
            sz_unlocking_script = (sz_signatures + push_data_size(sz_redeem_script) + sz_redeem_script)
        sz_length_unlocking_script = var_int_size(sz_unlocking_script)
        sz_sequence = 4
        sz_input = sz_prevout_txid + sz_prevout_index + sz_length_unlocking_script + sz_unlocking_script + sz_sequence
        
        sz_amount = 8
        if self._output['address'].kind == Address.ADDR_P2PKH:
            sz_locking_script = 25
        elif self._output['address'].kind == Address.ADDR_P2SH:
            sz_locking_script = 23
        sz_length_locking_script = var_int_size(sz_locking_script)
        sz_output = sz_amount + sz_length_locking_script + sz_locking_script
        
        return sz_version + 1 + sz_input + 1 + sz_output + sz_locktime
    
    def compute_fee(self):
        self._input['value']
        estimated_size = self.estimate_size()
        self._output['value'] = self._input['value'] - estimated_size * FEE_RATE
            
    def input_value(self):
        return self._input['value']

    def output_value(self):
        return self._output['value']

    def get_fee(self):
        return self.input_value() - self.output_value()
    
    def __str__(self):
        if not self.iscomplete:
            return None
        dtx = {'version': self.version, 'inputs': [self._input], 'outputs': [self._output], 'locktime': self.locktime, 'raw': self.raw.hex(), 'size': len(self.raw), 'fee': self.get_fee(), 'txid': self.txid().hex()}
        return dict.__str__(dtx)
    
    def __repr__(self):
        if not self.iscomplete:
            return None 
        return "<Transaction {}>".format(self.txid())