#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from wallet import *

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
        
    mnemonic = "zoo remove narrow bronze dizzy fashion scatter fossil ask clog bar slight"
            
    ks = DeterministicKeyStore.from_mnemonic( mnemonic )
    print( "Keystore: {0!s}".format( ks.dump() ) )
    
    wal = Wallet.from_mnemonic( mnemonic )
    print("Keystore: {0!s}".format( wal.keystore.dump() ))
    
    print( wal.addresses['external'][2] )
    print( wal.utxos )
    
    