#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket

from crypto import (dsha256, EllipticCurveKey)
from address import *
from network import make_message, version_message

SIGHASH_ALL = 0x01
SIGHASH_FORKID = 0x40
FORKID = 0x00
BCH_SIGHASH_TYPE = 0x41

TRANSACTION_VERSION_1 = 1 # version 2 transactions exist
SEQUENCE_NUMBER = 0xffffffff - 1

# OP codes (make a dictionnary ?)
OP_DUP = 0x76
OP_HASH160= 0xa9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xac

def construct_transaction( wifkey, receive_address, amount, locktime, prevout_id, prevout_index, prevout_value ):
    ''' Construct a Bitcoin Cash transaction with one input and one output.
    wifkey (str) : private key (Wallet Import Format)
    receive_address (str) : recipient address (legacy or cash format)
    amount (int) : amount in satoshis 
    prevout_id (str) : previous output transaction id
    prevout_index (int) : index of the output in the previous transaction
    prevout_value (int) : previous output value in satoshis'''
    
    # Creation of elliptic curve keys (private key + public key)
    eckey = EllipticCurveKey.from_wifkey( wifkey )
    
    # Public key and address (Public Key Hash)
    publicKey = eckey.serialized_pubkey()
    lengthPublicKey = bytes([len(publicKey)])
    print("Public key", publicKey.hex())
    sendaddr = Address.from_pubkey( publicKey )
    print("Sending address", sendaddr.to_cash())
    recaddr = Address.from_string( receive_address )
    print("Receiving address", recaddr.to_cash())
    print()
    
    # Version (little-endian)
    version = TRANSACTION_VERSION_1
    nVersion = version.to_bytes(4,'little')
    
    # Signature hash type (little-endian)
    hashtype = BCH_SIGHASH_TYPE
    nHashtype = hashtype.to_bytes(4,'little')
    
    # Sequence number (little-endian)
    sequence = SEQUENCE_NUMBER
    nSequence = sequence.to_bytes(4,'little')
    
    # Amount in satoshis (little-endian)
    nAmount = amount.to_bytes(8,'little')
    
    # Locktime (little-endian)
    nLocktime = locktime.to_bytes(4,'little')
    
    # Previous output hash (previous transaction id)
    prevHash = bytes.fromhex( prevout_id )[::-1]
    
    # Previous output index in this transaction
    prevIndex = prevout_index.to_bytes(4,'little')
    
    # Previous output value
    prevValue = prevout_value.to_bytes(8,'little')
    
    # Number of tx inputs
    input_count = 1
    nInputs = bytes([input_count])
    
    # Number of tx outputs
    output_count = 1
    nOutputs = bytes([output_count])
    
    # Input Public Key Hash
    pubkeyHash_in = sendaddr.hash_addr
    
    # Previous locking script
    prevLockingScript = bytes([OP_DUP]) + bytes([OP_HASH160]) + bytes([0x14]) + pubkeyHash_in + bytes([OP_EQUALVERIFY]) + bytes([OP_CHECKSIG])
    
    # Length of previous locking script
    lengthPrevLockingScript = bytes([len(prevLockingScript)])
    
    # Output Public Key Hash
    pubkeyHash_out = recaddr.hash_addr
    
    # Locking script
    lockingScript = bytes([OP_DUP]) + bytes([OP_HASH160]) + bytes([0x14]) + pubkeyHash_out + bytes([OP_EQUALVERIFY]) + bytes([OP_CHECKSIG])
    
    # Length of previous locking script
    lengthLockingScript = bytes([len(lockingScript)])
    
    outpoint = prevHash + prevIndex
    hashPrevouts = dsha256( outpoint )
    hashSequence = dsha256( nSequence )
    hashOutputs = dsha256( nAmount + lengthLockingScript + lockingScript )
    
    # --- Construct preimage ---
    # BIP-143
    preimage = b""
    
    preimage += nVersion # version
    preimage += hashPrevouts
    preimage += hashSequence
    preimage += outpoint
    preimage += lengthPrevLockingScript # length of the previous output locking script
    preimage += prevLockingScript # previous output locking script (scriptPubKey)
    preimage += prevValue # value of the previous output
    preimage += nSequence # sequence number
    preimage += hashOutputs
    preimage += nLocktime # locktime
    preimage += nHashtype # signature 4-bytes hash type
    
    print("PREIMAGE",preimage.hex())
    print()
    
    # We sign the double SHA256 hash of the preimage with our private key
    prehash = dsha256( preimage )
    signature = eckey.sign( prehash )
    lengthSigandHash = bytes([len(signature)+1])
    
    # --- Construct unlocking script ---
    unlockingScript = b""
    
    unlockingScript += lengthSigandHash # length of the signature
    unlockingScript += signature # DER-encoded signature of the double sha256 of the preimage
    unlockingScript += bytes([hashtype]) # signature 1-byte hash type
    unlockingScript += lengthPublicKey # length of serialized public key
    unlockingScript += publicKey # serialized public key
    
    lengthUnlockingScript = bytes([len(unlockingScript)])
    
    # --- Construct transaction ---
    rawtx = b""
    
    rawtx += nVersion # version
    rawtx += nInputs # input count
    
    rawtx += prevHash # previous output hash
    rawtx += prevIndex # previous output index
    rawtx += lengthUnlockingScript # length of the unlocking script
    rawtx += unlockingScript # unlocking script (scriptSig)
    rawtx += nSequence # sequence number
    
    rawtx += nOutputs # output count
    
    rawtx += nAmount # value of the output
    rawtx += lengthLockingScript # length of the output locking script
    rawtx += lockingScript # output locking script
    
    rawtx += nLocktime # locktime
    
    txid = dsha256( rawtx )[::-1]
    
    return rawtx, txid
    
    
if __name__ == '__main__':
    print()
    print("BROADCAST TRANSACTION")
    print("---------------------")
    print()
    
    # To send a new transaction, you have to modify:
    #   last_block (int) : height of the last block
    #   wifkey (str) : private key (WIF) of the sending address
    #   recipient_address (str) : receiving address
    #   receive_address (str) : recipient address (legacy or cash format)
    #   amount (int) : amount in satoshis 
    #   prevout_id (str) : previous output transaction id
    #   prevout_index (int) : index of the output in the previous transaction
    #   prevout_value (int) : previous output value in satoshis
    #   host (str) : IPv4 address of BCH node
    #   port (int) : port (DEFAULT_PORT = 8333)
    
    last_block = 524534
    
    wifkey = "5JNWbqkonfSFXmF5JxSgDAbmV21tVSbNiWpEPCymCw5cpkChcHg"
    recipient_address = "bitcoincash:qq7ur36zd8uq2wqv0mle2khzwt79ue9ty57mvd95r0"
    amount = 49116
    locktime = last_block # in electron : height of the last block
    prevout_id = "30745c2734e341b65cb348a3b73f1fbd810c516bf959f806862f3c703df972b7"
    prevout_index = 0
    prevout_value = 49366 # previous output value
    
    host = "88.130.71.155"
    port = 8333
    
    # Construction of transaction payload
    tx, txid = construct_transaction( wifkey, recipient_address, amount, locktime, prevout_id, prevout_index, prevout_value )
    print("RAW TRANSACTION")
    print(tx.hex())
    print()
    print("TRANSACTION ID")
    print(txid.hex())
    print()
    print("Transaction fees (sat)", prevout_value-amount)
    print()
    
    # Connexion to Bitcoin Cash network
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       
    print("connecting to node...")
    sock.connect((host,port))
    print("ok")
    
    # Version message
    ver_msg = make_message("version", version_message(last_block))
    print("Version message", ver_msg.hex())
    sock.send( ver_msg )
    
    m = sock.recv( 1024 )
    print("receive", m.hex())
    
    m = sock.recv( 1024 )
    print("receive", m.hex())
    
    # Transaction message
    tx_msg = make_message("tx", tx)
    print("Transaction message", tx_msg.hex())
    
    sock.send( tx_msg )
    
    m = sock.recv( 1024 )
    print("receive", m.hex())
    
    sock.close()
    print("end")