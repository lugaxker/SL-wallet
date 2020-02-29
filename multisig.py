#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (PrivateKey, PublicKey)
from address import Address
from script import *
from transaction import Transaction

from constants import Constants

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
    pubkeys = [ PublicKey.from_prvkey( wk ).to_ser() for wk in wifkeys_multisig]
    
    # Number of signatures required to unlock the multisig address
    nsigs = 2
    
    redeem_script = multisig_locking_script( pubkeys, nsigs )
    p2sh_addr = Address.from_script( redeem_script )
    
    # Transaction 1: p2pkh -> p2sh
    prvkey1 = PrivateKey.from_wif( wifkey1 )
    pubkey1 = PublicKey.from_prvkey( prvkey1 )
    input_address = Address.from_pubkey( pubkey1.to_ser() ).to_string() 
    output_address = p2sh_addr.to_cash()
    
    prevout_txid = "10e7ee10ecab3d16fcba5160792733dc2eeeb7270389d304832da3c9f5d31ef5"
    prevout_index = 1
    prevout_value = 80000 # previous output value
    locktime = 537937
    
    # Creation of the transaction    
    txin = {}
    txin['address'] = Address.from_pubkey( bytes.fromhex( pubkey1.to_ser(strtype=True) ) )
    txin['txid'] = prevout_txid
    txin['index'] = prevout_index
    txin['value'] = prevout_value
    txin['sequence'] = Constants.SEQUENCE_NUMBER
    txin['pubkeys'] = [ pubkey1.to_ser(strtype=True) ]
    txin['nsigs'] = 1
    
    tx1 = Transaction.from_inputs( [txin], locktime )
    
    txsize = ( tx1.estimate_size() + 32 
             + 2 * (Address.from_string( output_address ).kind == Constants.CASH_P2PKH) )
    fee = Constants.FEE_RATE * txsize 
    tx1.add_output( {'address': Address.from_string( output_address ), 'value': prevout_value - fee} )
    
    tx1.sign([prvkey1]) # signature 
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
    
    txin = {}
    txin['address'] = p2sh_addr
    txin['txid'] = prevout_txid
    txin['index'] = prevout_index
    txin['value'] = prevout_value
    txin['sequence'] = Constants.SEQUENCE_NUMBER
    txin['pubkeys'] = [pk.hex() for pk in pubkeys]
    txin['nsigs'] = nsigs
    
    tx2 = Transaction.from_inputs( [txin], locktime )
    
    txsize = ( tx2.estimate_size() + 32 
             + 2 * (Address.from_string( output_address ).kind == Constants.CASH_P2PKH) )
    
    fee = Constants.FEE_RATE * txsize 
    
    tx2.add_output( {'address': Address.from_string( output_address ), 'value': prevout_value - fee} )
    
    prvkeys = [ [PrivateKey.from_wif( wifkeys_multisig[2] ), PrivateKey.from_wif( wifkeys_multisig[0] )] ]
    tx2.sign(prvkeys)  
    tx2.serialize()
    
    fee = tx2.get_fee()
    print()
    print("--- TRANSACTION 2 ---")
    print("Input address (multisig)", input_address)
    print("Output address", output_address)
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
    
    
    