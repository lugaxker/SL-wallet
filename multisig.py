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
        
    wifkeys_multisig = [ "KyLxarqt64ndG3ENbLYp2922HKoasdQqd2sZS3VaQD5BF2pJLCmL",
                "KzqYDqNMVTPVeku7nwdFv3zPAQLwD2BnfEwgYYWeryyKbMDGTzwX",
                "L2wtM9x3JTvGa1YN6dpkmv4EdRsWTELJzdxsB2291KmSNe8Nof6c" ]
    
    # Sorted public keys involved in the multisig address
    pubkeys = [ PublicKey.from_prvkey( wk ) for wk in wifkeys_multisig]
    
    # Number of signatures required to unlock the multisig address
    nsigs = 2
    
    redeem_script = multisig_locking_script( pubkeys, nsigs )
    p2sh_addr = Address.from_script( redeem_script )
    
    print("multisig addr", p2sh_addr.to_cash())
    print()
    
    output_addr = Address.from_string("qz954pyuatjtyrf654ud2k55ykr6n7yl9ql8cvc955")
    
    # Transaction 1
    txin = {}
    txin['type'] = 'p2sh'
    txin['address'] = p2sh_addr
    txin['sequence'] = Constants.SEQUENCE_NUMBER
    txin['redeem_script'] = redeem_script
    txin['pubkeys'] = pubkeys
    txin['nsigs'] = nsigs
    txin['txid'] = "13d126438c07e7265e99c8b78bdc54b0abea15d34382a8fcb4fe6f9704137ad3"
    txin['index'] = 0
    txin['value'] = 175352
    
    txout1 = {}
    txout1['type'] = 'p2sh'
    txout1['address'] = p2sh_addr
    txout1['value'] = txin['value'] // 2 - 200
    
    txout2 = {}
    txout2['type'] = 'p2pkh'
    txout2['address'] = output_addr
    txout2['value'] = txin['value'] // 2 - 200
    
    tx = Transaction(2, [txin], [txout1, txout2], 0)
    prvkeys = [ [PrivateKey.from_wif( wifkeys_multisig[2] ), PrivateKey.from_wif( wifkeys_multisig[0] )] ]
    tx.sign( prvkeys, alg="schnorr" )
    
    txb = tx.serialize()
    txid = tx.txid().hex()
    fee = tx.get_fee()
    
    print("Transaction BCH de {} vers {} et {}".format(p2sh_addr.to_cash(), txout1['address'].to_cash(), txout2['address'].to_cash() ))
    print("size", len(txb))
    print("fee (satcashes)", fee)
    print(txb.hex())
    print("id:", txid)
    print()
    
    # Transaction 2
    txin2 = {}
    txin2['type'] = 'p2sh'
    txin2['address'] = p2sh_addr
    txin2['sequence'] = Constants.SEQUENCE_NUMBER
    txin2['redeem_script'] = redeem_script
    txin2['pubkeys'] = pubkeys
    txin2['nsigs'] = nsigs
    txin2['txid'] = "92e28ed95599db7ef68aae021baa9200c62efa5e63565c45dd5c146ad042fa95"
    txin2['index'] = 0
    txin2['value'] = 87476
    
    txout = {}
    txout['type'] = 'p2pkh'
    txout['address'] = output_addr
    txout['value'] = txin2['value'] - 400
    
    tx2 = Transaction(2, [txin2], [txout], 0)
    prvkeys = [ [PrivateKey.from_wif( wifkeys_multisig[0] ), PrivateKey.from_wif( wifkeys_multisig[1] )] ]
    tx2.sign( prvkeys, alg="ecdsa" )
    
    txb = tx2.serialize()
    txid = tx2.txid().hex()
    fee = tx2.get_fee()
    
    print("Transaction BCH de {} vers {}".format(p2sh_addr.to_cash(), txout['address'].to_cash() ))
    print("size", len(txb))
    print("fee (satcashes)", fee)
    print(txb.hex())
    print("id:", txid)
    print()
        
    