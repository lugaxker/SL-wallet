#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from wallet import *

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    # Mnemonic phrase
    f = open("wallet.json")
    walinfo = json.load(f)
    f.close()
    
    mnemonic = walinfo["mnemonic"]
    print()
    print("WALLET")
    print("  mnemonic:", mnemonic)
    
    wal = Wallet.from_mnemonic( mnemonic )
    print("  receiving address: ", wal.addresses[0][0])
    
    wal.update_utxos()
    print("  balance: {:.8f} BCH".format( wal.get_balance() / 1e8 ))
    
    output_address = "qq7ur36zd8uq2wqv0mle2khzwt79ue9ty57mvd95r0"
    amount = 48152
    rawtx, txid = wal.make_standard_transaction(output_address, amount)
    print()
    print("TRANSACTION")
    print(rawtx.hex())
    print(txid.hex())
    
    
    rawtx2, txid2 = wal.max_transaction( output_address )
    print()
    print("TRANSACTION MAX")
    print(rawtx2.hex())
    print(txid2.hex())
    
    
    
    print()
    #print(" addr balance", wal.get_address_balance(wal.addresses[0][0]) )
    #print(" total balance", wal.get_balance() )
    
    