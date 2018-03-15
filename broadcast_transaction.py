#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib

from address import *
from crypto import (double_sha256, EllipticCurveKey)

SIGHASH_ALL = 0x01
SIGHASH_FORKID = 0x40
BCH_SIGHASH_TYPE = 0x41

TRANSACTION_VERSION_1 = 1 # version 2 transactions exist
SEQUENCE_NUMBER = 0xffffffff - 1

# OP codes (make a dictionnary ?)
OP_DUP = 0x76
OP_HASH160= 0xa9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xac

def construct_transaction( wifkey, receive_address, amount, locktime ):
    ''' Construct a Bitcoin Cash transaction.
    wifkey (str) : private key (Wallet Import Format)
    receive_address (str) : recipient address (legacy or cash format)
    amount (int) : amount in satoshis '''
    
    
    
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
    
    # Version
    version = TRANSACTION_VERSION_1
    nVersion = version.to_bytes(4,'little')
    
    # Signature hash type
    hashtype = BCH_SIGHASH_TYPE
    nHashtype = hashtype.to_bytes(4,'little')
    
    # Sequence number
    sequence = SEQUENCE_NUMBER
    nSequence = sequence.to_bytes(4,'little')
    
    # Amount in satoshis
    nAmount = amount.to_bytes(4,'little')
    
    # Locktime
    nLocktime = locktime.to_bytes(4,'little')
    
    # Previous output hash (previous transaction id)
    prevoutHash = bytes.fromhex("bda694b9278473b080c97a37c5210aa7c87f80417d229ab5efc03f9c9909f5f5")
    
    # Previous output index in this transaction
    index = 1 # second output
    prevoutIndex = index.to_bytes(4,'little')
    
    # Number of tx inputs
    input_count = 1
    nInputs = bytes([input_count])
    
    # Number of tx outputs
    output_count = 1
    nOutputs = bytes([output_count])
    
    # Input Public Key Hash
    pubkeyHash_in = sendaddr.hash_addr[::-1]
    
    # Previous locking script
    prevLockingScript = bytes([OP_DUP]) + bytes([OP_HASH160]) + bytes([0x14]) + pubkeyHash_in + bytes([OP_EQUALVERIFY]) + bytes([OP_CHECKSIG])
    
    # Length of previous locking script
    lengthPrevLockingScript = bytes([len(prevLockingScript)])
    
    # Output Public Key Hash
    pubkeyHash_out = sendaddr.hash_addr[::-1]
    
    # Locking script
    lockingScript = bytes([OP_DUP]) + bytes([OP_HASH160]) + bytes([0x14]) + pubkeyHash_out + bytes([OP_EQUALVERIFY]) + bytes([OP_CHECKSIG])
    
    # Length of previous locking script
    lengthLockingScript = bytes([len(lockingScript)])
    
    # --- Construct preimage (temporary transaction) ---
    preimage = b""
    
    preimage += nVersion # version
    preimage += nInputs # input count
    
    preimage += prevoutHash # previous output hash
    preimage += prevoutIndex # previous output index
    preimage += lengthPrevLockingScript # length of the previous output locking script
    preimage += prevLockingScript # previous output locking script (scriptPubKey)
    preimage += nSequence # sequence number
    
    preimage += nOutputs # output count
    
    preimage += nAmount # value of the output
    preimage += lengthLockingScript # length of the output locking script
    preimage += lockingScript # output locking script
    
    preimage += nLocktime # locktime
    preimage += nHashtype # signature 4-bytes hash type
    
    print("1. Preimage\n", preimage.hex())
    print()
    
    # We sign the double SHA256 hash of the preimage with our private key
    preimage_hash = double_sha256( preimage )
    signature = eckey.sign( preimage_hash )
    lengthSig = bytes([len(signature)])
    
    # --- Construct unlocking script ---
    unlockingScript = b""
    
    unlockingScript += lengthSig # length of the signature
    unlockingScript += signature # DER-encoded signature of the double sha256 of the preimage
    unlockingScript += bytes([hashtype]) # signature 1-byte hash type
    unlockingScript += lengthPublicKey # length of serialized public key
    unlockingScript += publicKey # serialized public key
    
    lengthUnlockingScript = bytes([len(unlockingScript)])
    
    print("2. Unlocking script\n", unlockingScript.hex())
    print()
    
    # --- Construct transaction ---
    rawtx = b""
    
    rawtx += nVersion # version
    rawtx += nInputs # input count
    
    rawtx += prevoutHash # previous output hash
    rawtx += prevoutIndex # previous output index
    rawtx += lengthUnlockingScript # length of the previous output locking script
    rawtx += unlockingScript # previous output locking script (scriptPubKey)
    rawtx += nSequence # sequence number
    
    rawtx += nOutputs # output count
    
    rawtx += nAmount # value of the output
    rawtx += lengthLockingScript # length of the output locking script
    rawtx += lockingScript # output locking script
    
    rawtx += nLocktime # locktime
    
    print("3. Transaction\n", rawtx.hex())
    print()
    
    return rawtx.hex()
    
    
if __name__ == '__main__':
    print()
    print("BROADCAST TRANSACTION")
    print("---------------------")
    print()
    
    wifkey = "5KLnc4W67hQ2NYPky89WJYmEGfh42ddkui9YL7px9EnJq3KA6KE"
    recipient_address = "bitcoincash:qq7ur36zd8uq2wqv0mle2khzwt79ue9ty57mvd95r0"
    amount = 50000
    locktime = 0
    tx = construct_transaction( wifkey, recipient_address, amount, locktime )
    print("Raw transaction")
    print(tx)
    
    print()
