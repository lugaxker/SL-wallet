#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket

from crypto import (dsha256, EllipticCurveKey)
from address import *
from script import *
from transaction import Transaction
from network import make_message, version_message

SIGHASH_ALL = 0x01
SIGHASH_FORKID = 0x40
FORKID = 0x00
BCH_SIGHASH_TYPE = 0x41

TRANSACTION_VERSION_1 = 1 # version 2 transactions exist
SEQUENCE_NUMBER = 0xffffffff - 1

def construct_simple_transaction( wifkey, output_address, locktime, prevout_txid, prevout_index, prevout_value ):
    ''' Construct a Bitcoin Cash one-input / one-output transaction.
    wifkey (str) : private key (Wallet Import Format)
    output_address (str) : recipient address (legacy or cash format)
    prevout_txid (str) : previous output transaction id
    prevout_index (int) : index of the output in the previous transaction
    prevout_value (int) : previous output value in satoshis'''
    
    # Creation of elliptic curve keys (private key + public key)
    eckey = EllipticCurveKey.from_wifkey( wifkey )
    
    # Public key and address (Public Key Hash)
    publicKey = eckey.serialize_pubkey() 
    input_address = Address.from_pubkey( publicKey ).to_string()
    
    # Creation of the transaction
    tx = Transaction.minimal_transaction([publicKey.hex()], 1, input_address, output_address, prevout_txid, prevout_index, prevout_value, locktime)
    
    # Computation of fee
    tx.compute_fee()
    
    # Signing
    tx.sign([eckey])
    
    # Computation of raw transaction
    tx.serialize()

    fee = tx.get_fee()
    print("Input address", input_address)
    print("Output address", output_address)
    print("Amount sent (sat)", prevout_value-fee)
    print("Fee (sat)", fee)
    print()
    
    if tx.iscomplete:
        return tx.raw, tx.txid(), fee
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
    #   output_address (str) : recipient address (legacy or cash format) 
    #   prevout_txid (str) : previous output transaction id
    #   prevout_index (int) : index of the output in the previous transaction
    #   prevout_value (int) : previous output value in satoshis
    #   host (str) : IPv4 address of BCH node
    #   port (int) : port (DEFAULT_PORT = 8333)
    # and uncomment the connexion section below.
    
    last_block = 524534
    
    wifkey = "5JdSD57xmgcASmvXw4L1VqKQcboFjWdfA3GG63ShxA4kbE4ZHhh"
    output_address = "1GpSjtgw6fqfiZ6U5xxjbcUr4TWeCrrYj9"
    locktime = last_block # in electron : height of the last block
    prevout_txid = "0b6e3e3506df02cd5726c924f427cdfca302293107d66dd54d739bba9ae47030"
    prevout_index = 0
    prevout_value = 41424 # previous output value
    
    #host = "84.46.18.73"
    #port = 8333
    
    # Construction of transaction payload
    tx, txid, fee = construct_simple_transaction( wifkey, output_address, locktime, prevout_txid, prevout_index, prevout_value )
    print("RAW TRANSACTION")
    print(tx.hex())
    print("Size: {:d} bytes".format(len(tx)))
    print()
    print("Transaction identifier", txid.hex())
    print("Transaction fees (sat)", fee)
    print()
    
    ## Connexion to Bitcoin Cash network
    #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       
    #print("connecting to node...")
    #sock.connect((host,port))
    #print("ok")
    
    # Version message
    ver_msg = make_message("version", version_message(0xffff7f000001, 8333, last_block))
    print("Version message", ver_msg.hex())
    #sock.send( ver_msg )
    
    #m = sock.recv( 1024 )
    #print("receive", m.hex())
    
    #m = sock.recv( 1024 )
    #print("receive", m.hex())
    
    # Transaction message
    tx_msg = make_message("tx", tx)
    print("Transaction message", tx_msg.hex())
    
    #sock.send( tx_msg )
    
    #m = sock.recv( 1024 )
    #print("receive", m.hex())
    
    #sock.close()
    #print("end") 