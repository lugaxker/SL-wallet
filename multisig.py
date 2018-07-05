#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import EllipticCurveKey
from address import Address
from script import multisig_locking_script

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    wifkeys = [ "KzwQjFQPytv5x6w2cLdF4BSweGVCPEt8b8HbcuTi8e75LRQfw94L",
                "KyxzVE921zwDmctYGAMJJVU4DKh63Tntm3daWHRh1E4kP6Dhciti",
                "KxX6nGk7DLjfSF2n2eVK7fiw16ceQdVSgZ6tZM78DKBwZ8hytvyP" ]
                
    ## Bitcoin multisig the hard way - https://www.soroushjp.com/2014/12/20/bitcoin-multisig-the-hard-way-understanding-raw-multisignature-bitcoin-transactions/
    #wifkeys = ["5JruagvxNLXTnkksyLMfgFgf3CagJ3Ekxu5oGxpTm5mPfTAPez3",
               #"5JX3qAwDEEaapvLXRfbXRMSiyRgRSW9WjgxeyJQWwBugbudCwsk",
               #"5JjHVMwJdjPEPQhq34WMUhzLcEd4SD7HgZktEh8WHstWcCLRceV"]
    
    pubkeys = []
    for wk in wifkeys:
        eckey = EllipticCurveKey.from_wifkey( wk )
        pubkeys += [ eckey.serialize_pubkey() ]

    print("1st public key", pubkeys[0].hex())
    print("2nd public key", pubkeys[1].hex())
    print("3rd public key", pubkeys[2].hex())
    
    redeem_script = multisig_locking_script(2, pubkeys)
    print("Redeem script (multisig locking script)", redeem_script.hex() )
    
    p2sh_addr = Address.from_script( redeem_script )
    print("P2SH 2-of-3 multisig address (legacy)", p2sh_addr.to_legacy() )
    print("P2SH 2-of-3 multisig address (cash)", p2sh_addr.to_full_cash() )
    
    