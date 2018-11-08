#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# test 1
# claim tip private key cQPGJYAw68zmPzFHPCFFy4Xe74yTxacE3f1a1fFShbTbgckLz6dn
# refund tip private key cRiJZoyzCGqmbEKQpFgiazeFAzBtQw3KAbesXi98nafmMEgYAMDg
# block locktime 1265700
# redeem script 6376a914d610ce5425bdc1eb8a5bd7d4660cf92e4c35a84888670424501300b17576a914c794c754bd54715ea2638339a45f0a960ab8ab388868ac
# old non-working script: testnet address bchtest:pr4ggv7lk2mlvyzvk599np300sg2drklhca6athc6c 2NEdEUmjt2zvjw11y135G5Ms5YbJsPstsHP
# new working script: testnet address bchtest:pr0dhavddse46mxlk0s4y506wp36uzerzshhm8rlsn 2NDZbVuJwELtTEmubn7m1jVUEwx6bNnfaVL
# another script: testnet address bchtest:pqmljad8lc5rrl0p3rnlj5qlapr3pmshfce565zwyh 2MxMBzbEnrA1uj2ZRsu4qnb6hyUrMwz2Wcf

# Testnet
# explorers https://www.blocktrail.com/tBCC https://tbch.blockdozer.com/
# testnet faucet https://coinfaucet.eu/en/bch-testnet/
# donate mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB

from crypto import (PublicKey, PrivateKey)
from address import Address
from script import *
from transaction import Transaction
from network import Network

from constants import *

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
        
    # Tip private key
    # mainnet: Kz2GqdB5f5JWEYn1znS8bk2aUqg4J8WXycs6uEnwCUobRsib6N2R
    # testnet: cQPGJYAw68zmPzFHPCFFy4Xe74yTxacE3f1a1fFShbTbgckLz6dn
    claim_secret = 0x53a0e9e7894f4f77fba3cc62d9dcb82d61d085c34f7fa2a712e26d62ae4f42a3
    claim_prvkey = PrivateKey( claim_secret )
    print("claim tip")
    print( claim_prvkey )
    claim_pubkey = PublicKey.from_prvkey( claim_prvkey )
    claim_address = Address.from_pubkey( claim_pubkey )
    print( claim_address.to_full_cash() )
    print( claim_address.to_legacy() )
    print( claim_address.h.hex() )
    
    # Refund private key
    # mainnet: L1MK6tz8mD9WRnr9RqsbDg9BYktUkUwd6ZWQRHgdHU1m6VbUPkdz
    # testnet: cRiJZoyzCGqmbEKQpFgiazeFAzBtQw3KAbesXi98nafmMEgYAMDg
    refund_secret = 0x7b42a6f4f75cb14d701965b9da9245940837b4b3d8073bd2cf228605c1f0fe40
    refund_prvkey = PrivateKey( refund_secret )
    print("refund tip")
    print( refund_prvkey )
    refund_pubkey = PublicKey.from_prvkey( refund_prvkey )
    refund_address = Address.from_pubkey( refund_pubkey )
    print( refund_address.to_full_cash() )
    print( refund_address.h.hex() )
    
    # Block time lock
    locktime = 1266507
    
    redeemScript = expiring_tip_locking_script( locktime, claim_address, refund_address )
    print( redeemScript.hex() )
    contract_address = Address.from_script( redeemScript )
    print( contract_address )
    print( contract_address.to_legacy() )
    print( contract_address.h.hex())
    
    # Building transaction
    prevout_txid = "50883f023c5c962d25c7e14b91662a1316a065208f7fb0276943026661040d7b"
    prevout_index = 0
    prevout_value = 100000
    output_address = claim_address
    fee = 1000
    
    txin = {}
    txin['address'] = contract_address
    txin['txid'] = prevout_txid
    txin['index'] = prevout_index
    txin['value'] = prevout_value
    txin['sequence'] = Constants.SEQUENCE_NUMBER
    txin['pubkeys'] = [ refund_pubkey ]
    txin['nsigs'] = 1
    txin['redeem_script'] = redeemScript
    
    txout = {}
    txout['address'] = output_address
    txout['value'] = prevout_value - fee
    txout['type'] = 'p2pkh'
    
    tx = Transaction( Constants.TX_VERSION, [txin], [txout], 1266507)
    tx.sign( [ refund_prvkey ] )
    print(tx.serialize().hex())
    
    # other script x + 3 = 5
    # done: 117751f1136f12e46a46d87fb7dc618ac314a76ffca9faa7d9849099d62d2f7e (BCH testnet)