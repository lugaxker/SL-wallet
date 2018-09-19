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
    
    @classmethod
    def from_inputs(self, txins, locktime=0):
        return self( 1, txins, [], locktime )
    
    @classmethod
    def from_outputs(self, txouts, locktime=0):
        return self( 1, [], txouts, locktime )
    
    @classmethod
    def from_serialized(self, raw):
        assert isinstance( raw, bytes )
        self.raw = raw
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
                t, signatures, pubkeys, address = parse_unlocking_script( unlockingScript )
                if t in ("p2pk", "p2pkh", "p2sh"):
                    txin['type'] = t
                if signatures:
                    txin['signatures'] = [sig.hex() for sig in signatures]
                    txin['nsigs'] = len(signatures)
                if pubkeys:
                    txin['pubkeys'] = pubkeys
                if address:
                    txin['address'] = address
            txin['sequence'], raw = read_bytes(raw, 4, int, 'little')
            txins.append( txin )
        
        output_count, raw = read_var_int(raw)
        txouts = []
        for i in range(output_count):
            txout = {}
            txout['value'], raw = read_bytes(raw, 8, int, 'little')
            scriptsize, raw = read_var_int( raw )
            lockingScript, raw = read_bytes(raw, scriptsize, bytes, 'big')
            t, address, data = parse_locking_script( lockingScript )
            if t in ("p2pk", "p2pkh", "p2sh", "data"):
                txout['type'] = t
            if address:
                txout['address'] = address
            if data:
                assert t == "data"
                txout['data'] = {'protocol':data[0], 'prefix':data[1], 'content':data[2]}
            txouts.append( txout )
        
        locktime, raw = read_bytes(raw, 4, int, 'little')
        
        return self(version, txins, txouts, locktime)
    
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
        if txout['type'] in ("p2pkh", "p2sh"):
            lockingScript = locking_script( txout['address'] )
        elif txout['type'] == "p2pk":
            raise TransactionError("cannot serialize p2pk output")
        elif txout['type'] == "data":
            
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
        
        return nVersion + txins + txouts + nLocktime
    
    def is_complete(self):
        if not self._inputs:
            return False
        
        if not self._outputs:
            return False
        
        # Signatures
        for txin in self._inputs:
            if not 'signatures' in txin:
                return False
            else:
                sigs = txin['signatures']
                if txin['nsigs'] != len(sigs):
                    return False
        return True
                
        
    def txid(self):
        '''Returns transaction identifier.'''
        if self.is_complete():
            return dsha256( self.serialize() )[::-1]
        else:
            return None
        
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
        try:
            txid = self.txid()
        except:
            dtx = {'version': self.version, 'inputs': self._inputs, 'outputs': self._outputs, 'locktime': self.locktime}
        else:
            if txid:
                dtx = {'version': self.version, 'inputs': self._inputs, 'outputs': self._outputs, 'locktime': self.locktime, 'txid':txid.hex()}
            else:
                dtx = {'version': self.version, 'inputs': self._inputs, 'outputs': self._outputs, 'locktime': self.locktime}
        
        return dict.__str__(dtx)
    
    def __repr__(self):
        return "<Transaction {}>".format(self.txid())
    
if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    print()
    print("- classic tx")
    raw = bytes.fromhex( "0100000001f475687abdcbda8c16d76eaf032f1b0df06281a4a1ba19fa7585f7307a9895be000000006a4730440220151779354bd622f0d680fa3c579b9a53d7bda1fe285efc162fd4b6258364219802207f783ee9cd6e13ccea9cbb71169b04ea2af89a027d49f4567e33c1f1c2761e0d412102da57428231cd3b1892287ec093f899c4fca16bb6944ae9ede866995d016c094cfeffffff01bc5f0000000000001976a91497982cc1e24683fa9ed357c10b83f8a28f6021a988ac6cf50700" )
    tx = Transaction.from_serialized( raw )
    print( tx )
    if tx.txid():
        print("id {}".format(tx.txid().hex()))
    
    # coinbase
    print()
    print("- coinbase")
    cb = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"
    raw = bytes.fromhex( cb )
    tx = Transaction.from_serialized( raw )
    print( tx )
    if tx.txid():
        print("id {}".format(tx.txid().hex()))
    
    # multisig output
    print()
    print("- multisig output")
    mso = "0100000001f51ed3f5c9a32d8304d3890327b7ee2edc3327796051bafc163dabec10eee710010000006a473044022045ba696fd4765b3088248beae40e300387b17dee6a3e688020f8ee379202f2d802200743840e48d917f6191a8c6fc82164e46986b4b19e811813bee8e0b8e0c1d3e7412103caec4587bf1e3bab82bc11ec862d62891ca62c7283aa01d215bc38be6b8cbac4feffffff01c23701000000000017a91486b192cc018924737814981cfa12b573ca1118fd8751350800"
    raw = bytes.fromhex( mso )
    tx = Transaction.from_serialized( raw )
    print( tx )
    if tx.txid():
        print("id {}".format(tx.txid().hex()))
    
    # multisig input
    print()
    print("- multisig input")
    msi = "01000000019c2cdd2b117d3a7e310c244ac056c9a86777589e9f56d6aa28d23554ff43086800000000fc0047304402205cc4f55c318ed1c3b24b58705a9691e00a6b78cda083747c8166987125121a1b0220694cd3c844c11964e57b539d29aa9bac308555a22dc8175880097fbf4f5fcd714147304402207523060936c3057bd55a81ede5c42d753858a08b0504e0fdbcc84095f21fcecb02202a5555cd8edc52ad406f35be35445adc8f9f7e5bc0dfa706ad5cf806576395b0414c69522103d307d94c5d7cbf8ce1a6b62b3286eafddf13065ad4b101f7b7a222f673f9508c21022d8de3ea6e5eb022fe37ccb6464da662c0105bfab676a8dd53f1fb2756ab5dfc2102b2afb5a9f59ea62136e775c13457de2951bce4f433f738e9ceb2848a7e369c2a53aefeffffff011a350100000000001976a914dd4bb0b80cfe777389867583841f13b3df8fa47588acfa350800"
    raw = bytes.fromhex( msi )
    tx = Transaction.from_serialized( raw )
    print( tx )
    if tx.txid():
        print("id {}".format(tx.txid().hex()))
    assert tx.serialize() == raw
    
    # memo 
    print()
    print("- memo post")
    memop = "01000000017fc36050d3823a936dbc44bed0f16e3d5a31241b24c29d8c5dd9bcf4d8e732ed000000006b483045022100d142f369f8adf8f9c94b4362a54b37af0e2b1a262770312fb46910dea164f3190220755c78910c785638b081b56dcd5a247384cf2ed73b020e55dec2b57f7963cf654121025e108348d065924625988ae7e6606a1c051dd650b90bb31c601f9e91569eb22cffffffff0297090000000000001976a9144c94f3ffb09a3ee4fc7c1e733e576c8f634e065488ac00000000000000003f6a026d023a4d656d6f206973207468652066697273742064617070207468617420686173206d6f7265207573657273207468616e20696e766573746f72732e00000000"
    raw = bytes.fromhex( memop )
    tx = Transaction.from_serialized( raw )
    print( tx )
    #if tx.txid():
        #print("id {}".format(tx.txid().hex()))