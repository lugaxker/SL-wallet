#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
from keys import EllipticCurveKey

def sha256(x):
    '''Simple wrapper of hashlib sha256.'''
    return hashlib.sha256(x).digest()

def broadcast_transaction( wifkey, recipient_address, amount ):
    ''' Broadcast a transaction on Bitcoin Cash network.
    wifkey (str) : private key (Wallet Import Format)
    recipient_address (str) : recipient address (legacy or cash format)
    amount (int) : amount in satoshis '''
    
    # Creation of elliptic curve keys (private key + public key)
    eckey = EllipticCurveKey.from_wifkey( wifkey )
    
    # Example of signature
    msg = bytes.fromhex("ae55983f")
    msg_hash = sha256(msg)
    signature = eckey.sign(msg_hash)
    print("Example of signature for msg = {} : {}".format(msg.hex(), signature.hex()))
    
if __name__ == '__main__':
    wifkey = "5HqspAdCGnyUSpKmTv3Co5K5WmoP324XAgSei2qFmdfiYJYJN74"
    recipient_address = ""
    amount = 0
    broadcast_transaction( wifkey, recipient_address, amount )
