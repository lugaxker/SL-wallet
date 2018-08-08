#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (dsha256, PrivateKey, PublicKey)
from address import *
from script import *

from util import (read_bytes, var_int, read_var_int, var_int_size)

from constants import *

DEFAULT_SEQUENCE_NUMBER = 0xffffffff - 1
BCH_SIGHASH_TYPE = 0x41

class TransactionError(Exception):
    '''Exception used for Transaction errors.'''

class Transaction:
    ''' Transaction. 
    input . '''
    
    def __init__(self, version = 1, txins = [], txouts = [], locktime = 0):
        self._inputs = txins
        self._outputs = txouts
        self.version = version
        self.locktime = locktime
        self.hashtype = BCH_SIGHASH_TYPE # hardcoded signature hashtype
        
        self.iscomplete = False
    
    @classmethod
    def from_inputs(self, txins, locktime=0):
        return self( 1, txins, [], locktime )
    
    @classmethod
    def from_outputs(self, txouts, locktime=0):
        return self( 1, [], txouts, locktime )
    
    # TODO: parse scripts
    @classmethod
    def deserialize(self, raw):
        assert isinstance( raw, bytes )
        version, raw = read_bytes(raw, 4, int, 'little')
        
        input_count, raw = read_var_int(raw)
        txins = []
        for i in range(input_count):
            txin = {}
            txin['txid'], raw = read_bytes(raw, 32, hex, 'little')
            txin['index'], raw = read_bytes(raw, 4, int, 'little')
            scriptsize, raw = read_var_int( raw )
            unlockingScript, raw = read_bytes(raw, scriptsize, bytes, 'big')
            if (txin['txid'] == "00"*32) & (txin['index'] == 0xffffffff):
                # Coinbase input
                txin['type'] = "coinbase"
            else:
                # TODO: parse unlocking script (type (p2pk, p2pkh, p2sh), pubkeys, signatures, address?)
                pass
            txin['sequence'], raw = read_bytes(raw, 4, int, 'little')
            txins.append( txin )
        
        output_count, raw = read_var_int(raw)
        txouts = []
        for i in range(output_count):
            txout = {}
            txout['value'], raw = read_bytes(raw, 8, int, 'little')
            scriptsize, raw = read_var_int( raw )
            lockingScript, raw = read_bytes(raw, scriptsize, bytes, 'big')
            # TODO: parse locking script (address)
            txouts.append( txout )
        
        locktime, raw = read_bytes(raw, 4, int, 'little')
        
        return self(1, [],[])
    
    def add_input(self, txin):
        self._inputs.append( txin )
    
    def add_output(self, txout):
        self._outputs.append( txout )
    
    def get_preimage_script(self, txin):
        ''' Returns the previous locking script for a P2PKH address,
        and the redeem script for a P2SH address (only multisig for now). '''
        input_addr = txin['address']
        if input_addr.kind == Constants.CASH_P2PKH:
            return locking_script( input_addr )
        elif input_addr.kind == Constants.CASH_P2SH:
            return multisig_locking_script( txin['pubkeys'], txin['nsigs'] )
        return None
    
    def serialize_outpoint(self, txin):
        ''' Serializes the outpoint of the input (prev. txid + prev. index).'''        
        return (bytes.fromhex( txin['txid'] )[::-1] +
                txin['index'].to_bytes(4,'little') )
    
    def serialize_input(self, txin):
        ''' Serializes an input: outpoint (previous output tx id + previous output index)
        + unlocking script (scriptSig) with its size + sequence number. '''
        outpoint  = self.serialize_outpoint(txin)
        signatures = [bytes.fromhex(sig) for sig in txin['signatures']]
        unlockingScript = unlocking_script(txin['address'], txin['pubkeys'], signatures)
        unlockingScriptSize = var_int( len( unlockingScript ) )
        nSequence = txin['sequence'].to_bytes(4,'little')
        return outpoint + unlockingScriptSize + unlockingScript + nSequence
    
    def serialize_output(self, txout):
        ''' Serializes an output: value + locking script (scriptPubkey) with its size.'''
        nAmount = txout['value'].to_bytes(8,'little')
        lockingScript = locking_script( txout['address'] )
        lockingScriptSize = var_int( len(lockingScript) )
        return nAmount + lockingScriptSize + lockingScript
        
    def serialize_preimage(self, txin):
        ''' Serializes the preimage of the transaction (BIP-143).'''
        nVersion = self.version.to_bytes(4,'little')
        nLocktime = self.locktime.to_bytes(4,'little')
        nHashtype = self.hashtype.to_bytes(4,'little') # signature hashtype (little-endian)
        
        hashPrevouts = dsha256( bytes().join( self.serialize_outpoint(txi) for txi in self._inputs ) )
        hashSequence = dsha256( bytes().join( txi['sequence'].to_bytes(4,'little') for txi in self._inputs ) )
        
        outpoint = self.serialize_outpoint(txin)
        prevLockingScript = self.get_preimage_script(txin)
        prevLockingScriptSize = var_int( len(prevLockingScript) )
        prevValue = txin['value'].to_bytes(8,'little')
        nSequence = txin['sequence'].to_bytes(4,'little')
        
        hashOutputs = dsha256( bytes().join( self.serialize_output(txo) for txo in self._outputs ) )
        
        return (nVersion + hashPrevouts + hashSequence + outpoint + 
                prevLockingScriptSize + prevLockingScript + prevValue +
                nSequence + hashOutputs + nLocktime + nHashtype)
    
    def serialize(self):
        ''' Serializes the transaction. '''
        nVersion = self.version.to_bytes(4,'little') # version (little-endian)
        nLocktime = self.locktime.to_bytes(4,'little') # lock time (little-endian)        
        
        # Transactions inputs
        txins = var_int(len(self._inputs)) + bytes().join( self.serialize_input(txin) for txin in self._inputs )
        
        # Transaction outputs
        txouts = var_int(len(self._outputs)) + bytes().join( self.serialize_output(txout) for txout in self._outputs )
        
        self.raw = nVersion + txins + txouts + nLocktime
        self.iscomplete = True
        return self.raw
        
    def txid(self):
        '''Returns transaction identifier.'''
        if not self.iscomplete:
            return None
        return dsha256( self.raw )[::-1]
        
    def sign(self, private_keys):
        '''Signs the transaction. 
        prvkeys (list of PrivateKey items)'''
        for i, txin in enumerate(self._inputs):
            prvkeys = private_keys[i] 
            if isinstance( prvkeys, PrivateKey):
                assert txin['nsigs'] == 1
                prvkeys = [ prvkeys ]
            elif isinstance( prvkeys, list ):
                assert len( prvkeys ) == txin['nsigs']
                # Sorting keys
                sorted_prvkeys = []
                for prvkey in prvkeys:
                    pubkey = PublicKey.from_prvkey( prvkey )
                    assert(pubkey in txin['pubkeys'])
                    sorted_prvkeys += [(txin['pubkeys'].index(pubkey), prvkey)]
                sorted_prvkeys.sort(key = lambda x: x[0])
                prvkeys = [k[1] for k in sorted_prvkeys]
            else:
                raise TransactionError('wrong type for private keys')
            prehash = dsha256( self.serialize_preimage(txin) )
            hashtype = bytes( [self.hashtype & 0xff] ).hex()
            self._inputs[i]['signatures'] = [ prvkey.sign( prehash, strtype=True ) + hashtype for prvkey in prvkeys ]
          
    def estimate_input_size(self, txin):
        sz_prevout_txid = 32
        sz_prevout_index = 4
        if txin['address'].kind == Constants.CASH_P2PKH:
            sz_sig = 0x48
            if txin['pubkeys'][0].is_compressed():
                sz_pubkey = 0x21
            else:
                sz_pubkey = 0x41
            sz_unlocking_script = (push_data_size(sz_sig) + sz_sig 
                                   + push_data_size(sz_pubkey) + sz_pubkey)
        elif txin['address'].kind == Constants.CASH_P2SH:
            # only multisig for now
            sz_signatures = 1 + txin['nsigs'] * (1 + 0x48)
            sz_pubkeys = 0
            for pubkey in txin['pubkeys']:
                if pubkey.is_compressed():
                    sz_pubkeys += 1 + 0x21
                else:
                    sz_pubkeys += 1 + 0x41
            sz_redeem_script = 1 + sz_pubkeys + 2
            sz_unlocking_script = (sz_signatures + push_data_size(sz_redeem_script) 
                                   + sz_redeem_script)
            
        sz_length_unlocking_script = var_int_size(sz_unlocking_script)
        sz_sequence = 4
        return sz_prevout_txid + sz_prevout_index + sz_length_unlocking_script + sz_unlocking_script + sz_sequence
    
    def estimate_output_size(self, txout):
        sz_amount = 8
        if txout['address'].kind == Constants.CASH_P2PKH:
            sz_locking_script = 25
        elif txout['address'].kind == Constants.CASH_P2SH:
            sz_locking_script = 23
        sz_length_locking_script = var_int_size(sz_locking_script)
        return sz_amount + sz_length_locking_script + sz_locking_script
        
    def estimate_size(self):
        sz_version = 4
        sz_inputs = sum( self.estimate_input_size(txin) for txin in self._inputs )
        sz_outputs = sum( self.estimate_output_size(txout) for txout in self._outputs )
        sz_locktime = 4
        
        return (sz_version + var_int_size(sz_inputs) + sz_inputs
                + var_int_size(sz_outputs) + sz_outputs + sz_locktime)
        
    def input_value(self):
        return sum( txin['value'] for txin in self._inputs )

    def output_value(self):
        return sum( txout['value'] for txout in self._outputs )

    def get_fee(self):
        return self.input_value() - self.output_value()
    
    def __str__(self):
        if not self.iscomplete:
            return None
        dtx = {'version': self.version, 'inputs': self._inputs, 'outputs': self._outputs, 'locktime': self.locktime, 'raw': self.raw.hex(), 'size': len(self.raw), 'fee': self.get_fee(), 'txid': self.txid().hex()}
        return dict.__str__(dtx)
    
    def __repr__(self):
        if not self.iscomplete:
            return None 
        return "<Transaction {}>".format(self.txid())