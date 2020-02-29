#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket

from crypto import (dsha256, PrivateKey, PublicKey)
from address import *
from script import *
from transaction import Transaction
from network import *

SIGHASH_ALL = 0x01
SIGHASH_FORKID = 0x40
FORKID = 0x00
BCH_SIGHASH_TYPE = 0x41

TRANSACTION_VERSION_1 = 1 # version 2 transactions exist

from constants import Constants

def construct_simple_transaction( wifkey, output_addr, locktime, prevout_txid, prevout_index, prevout_value ):
    ''' Construct a Bitcoin Cash one-input / one-output transaction.
    wifkey (str) : private key (Wallet Import Format)
    output_addr (str) : recipient address (legacy or cash format)
    prevout_txid (str) : previous output transaction id
    prevout_index (int) : index of the output in the previous transaction
    prevout_value (int) : previous output value in satoshis'''
    
    
    # Private key
    prvkey = PrivateKey.from_wif( wifkey )
    
    # Public key and address (Public Key Hash)
    pubkey = PublicKey.from_prvkey( prvkey )
    input_address = Address.from_pubkey( pubkey )
    
    # Output address
    output_address = Address.from_string( output_addr )
    
    # Creation of the transaction   
    txin = {}
    txin['address'] = input_address
    txin['txid'] = prevout_txid
    txin['index'] = prevout_index
    txin['value'] = prevout_value
    txin['sequence'] = Constants.SEQUENCE_NUMBER
    txin['pubkeys'] = [ pubkey ]
    txin['nsigs'] = 1
    
    tx = Transaction.from_inputs( [txin], locktime )
    
    txsize = ( tx.estimate_size() + 32 
             + 2 * (output_address.kind == Constants.CASH_P2PKH) )
    fee = Constants.FEE_RATE * txsize 
    txout = {}
    txout['address'] = output_address
    txout['value'] = prevout_value - fee
    tx.add_output( txout )
    
    prvkeys = [ prvkey ]
    tx.sign(prvkeys)  
    rawtx = tx.serialize()

    fee = tx.get_fee()
    print("Input address", input_address.to_cash())
    print("Output address", output_address.to_cash())
    print("Amount sent (sat)", prevout_value-fee)
    print("Fee (sat)", fee)
    print()
    
    if tx.iscomplete:
        return rawtx, tx.txid(), fee
    else: 
        return None
    
    
if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    print()
    print("BROADCAST TRANSACTION")
    print("---------------------")
    print()
    
    # To send a new transaction, you have to modify:
    #   last_block (int) : height of the last block
    #   wifkey (str) : private key (WIF) of the sending address
    #   output_addr (str) : recipient address (legacy or cash format) 
    #   prevout_txid (str) : previous output transaction id
    #   prevout_index (int) : index of the output in the previous transaction
    #   prevout_value (int) : previous output value in satoshis
    #   host (str) : IPv4 address of BCH node
    #   port (int) : port (DEFAULT_PORT = 8333)
    # and uncomment the connexion section below.
    
    last_block = 540937
    
    wifkey = "5JdSD57xmgcASmvXw4L1VqKQcboFjWdfA3GG63ShxA4kbE4ZHhh"
    output_addr = "1GpSjtgw6fqfiZ6U5xxjbcUr4TWeCrrYj9"
    locktime = last_block # in electron : height of the last block
    prevout_txid = "0b6e3e3506df02cd5726c924f427cdfca302293107d66dd54d739bba9ae47030"
    prevout_index = 0
    prevout_value = 41424 # previous output value
    
    # Construction of transaction payload
    tx, txid, fee = construct_simple_transaction( wifkey, output_addr, locktime, prevout_txid, prevout_index, prevout_value )
    print("RAW TRANSACTION")
    print(tx.hex())
    print("Size: {:d} bytes".format(len(tx)))
    print()
    print("Transaction identifier", txid.hex())
    print("Transaction fees (sat)", fee)
    print()
    
    ## Connexion to Bitcoin Cash network
    #host = "46.28.204.198"
    #port = 8333
    #peer_address = (host, port)
    
    ## Version message
    #print()
    #network_manager = Network(peer_address, last_block)
    #network_manager.start()
    #time.sleep(5)
    #network_manager.shutdown()