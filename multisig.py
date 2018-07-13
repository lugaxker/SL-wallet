#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import EllipticCurveKey
from address import Address
from script import *
from transaction import Transaction

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
        
    wifkey1 = "L239DGsGnzuvsDQcNDrkBk5WGNhMqQRkUkFSp3bCycWwR8i7Xvod"
    
    wifkeys_multisig = [ "KzwQjFQPytv5x6w2cLdF4BSweGVCPEt8b8HbcuTi8e75LRQfw94L",
                "Ky4yk7uTBZ1EDbqyVfkvoZXURpWdRCxTpCERZb4gkn67fY8kK95R",
                "Kz3Htg8mSfC997qkBxpVCdxYhEoRcFj5ikUjE96ipVAJPou7MwRD" ]
    
                
    ## Bitcoin multisig the hard way - https://www.soroushjp.com/2014/12/20/bitcoin-multisig-the-hard-way-understanding-raw-multisignature-bitcoin-transactions/
    #wifkeys = ["5JruagvxNLXTnkksyLMfgFgf3CagJ3Ekxu5oGxpTm5mPfTAPez3",
               #"5JX3qAwDEEaapvLXRfbXRMSiyRgRSW9WjgxeyJQWwBugbudCwsk",
               #"5JjHVMwJdjPEPQhq34WMUhzLcEd4SD7HgZktEh8WHstWcCLRceV"]
    
    # Sorted public keys involved in the multisig address
    pubkeys = [ EllipticCurveKey.from_wifkey( wk ).serialize_pubkey() for wk in wifkeys_multisig ]
    
    # Number of signatures required to unlock the multisig address
    nsigs = 2
    
    redeem_script = multisig_locking_script( pubkeys, nsigs )
    p2sh_addr = Address.from_script( redeem_script )
    
    # Transaction 1: p2pkh -> p2sh
    eckey1 = EllipticCurveKey.from_wifkey( wifkey1 )
    input_address = Address.from_pubkey( eckey1.serialize_pubkey() ).to_string() 
    output_address = p2sh_addr.to_cash()
    
    prevout_txid = "10e7ee10ecab3d16fcba5160792733dc2eeeb7270389d304832da3c9f5d31ef5"
    prevout_index = 1
    prevout_value = 80000 # previous output value
    locktime = 537937
    
    # Creation of the transaction
    
    tx1 = Transaction.minimal_transaction( [eckey1.serialize_pubkey().hex() ], 1, input_address, output_address, prevout_txid, prevout_index, prevout_value, locktime)
    tx1.compute_fee()
    tx1.sign([eckey1]) # signature 
    tx1.serialize() # computation of raw transaction
    
    
    
    fee = tx1.get_fee()
    print()
    print("--- TRANSACTION 1 ---")
    print("Input address", input_address)
    print("Output address", output_address)
    print("Amount", prevout_value-fee)
    print("Fee: {:d} sats".format(fee) )
    print("Size: {:d} bytes".format(len(tx1.raw)))
    
    print("Raw tx", tx1.raw.hex())
    
    
    
    # Transaction 2: p2sh -> p2pkh
    input_address = p2sh_addr.to_cash()
    output_address = "qrw5hv9cpnl8wuufse6c8pqlzwealrayw54hhf2d20"
    
    prevout_txid = "680843ff5435d228aad6569f9e587767a8c956c04a240c317e3a7d112bdd2c9c"
    prevout_index = 0
    prevout_value = 79810
    locktime = 538106
    
    hexpubkeys = [pk.hex() for pk in pubkeys]
    tx2 = Transaction.minimal_transaction(hexpubkeys, nsigs, input_address, output_address, prevout_txid, prevout_index, prevout_value, locktime)
    
    tx2.compute_fee()
    eckeys = [ EllipticCurveKey.from_wifkey( wifkeys_multisig[2]), EllipticCurveKey.from_wifkey(wifkeys_multisig[0]) ]
    tx2.sign(eckeys)  
    tx2.serialize()
    
    fee = tx2.get_fee()
    print()
    print("--- TRANSACTION 2 ---")
    print("Input address", input_address)
    print("Output address (multisig)", output_address)
    print("Amount", prevout_value-fee)
    print("Fee: {:d} sats".format(fee) )
    print("Size: {:d} bytes".format(len(tx2.raw)))
    print("Raw tx", tx2.raw.hex())
    
    print()
    print("Private keys (WIF)")
    for wk in wifkeys_multisig:
        print(" ",wk)
    
    print()
    print("Public keys")
    for pubkey in pubkeys:
        print(" ", pubkey.hex())
    
    
    