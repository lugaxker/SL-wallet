#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

from wallet import *

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")

    wal = Wallet.load( "wallet.json" )
        
    wal.start_network()
    
    time.sleep(10)
    
    wal.save()
    wal.stop_network()
    
    #print()
    #print("WALLET")
    #print("  mnemonic:", wal.keystore.mnemonic)
    #print("  receiving address: ", wal.recv_addresses[0].to_cash())
    
    #wal.update_utxos()
    #print("  balance: {:.8f} BCH".format( wal.get_balance() / 1e8 ))
    
    #print()
    #wal.save()
    
    #output_address = Address.from_string( "qq7ur36zd8uq2wqv0mle2khzwt79ue9ty57mvd95r0" )
    #amount = 48152
    #rawtx, txid = wal.make_standard_transaction(output_address, amount)
    #print()
    #print("TRANSACTION")
    #print(rawtx.hex())
    #print(txid.hex())
    
    
    
    