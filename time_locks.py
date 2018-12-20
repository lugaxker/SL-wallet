#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Bitcoin Cash Testnet
#  explorers: https://tbch.blockdozer.com/ & https://www.blocktrail.com/tBCC
#  faucet: https://coinfaucet.eu/en/bch-testnet/ (donate address: mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB)

from crypto import (PublicKey, PrivateKey)
from address import Address
from script import *
from transaction import Transaction
from network import Network

from constants import *
from util import push_data, sequence_number

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    print()
    
    ''' My addresses '''
    print("ADDRESSES")
    print()
    
    # Claim private key
    #  mainnet: Kz2GqdB5f5JWEYn1znS8bk2aUqg4J8WXycs6uEnwCUobRsib6N2R
    #  testnet: cQPGJYAw68zmPzFHPCFFy4Xe74yTxacE3f1a1fFShbTbgckLz6dn
    # Claim address
    #  testnet: bchtest:qrtppnj5yk7ur6u2t0tagesvlyhycddgfq630lqqkh 
    #           n12q2oecWxTmcaMmMShnqvtC4FL59LCaBE (legacy)
    claim_secret = 0x53a0e9e7894f4f77fba3cc62d9dcb82d61d085c34f7fa2a712e26d62ae4f42a3
    claim_prvkey = PrivateKey( claim_secret )
    print("Claim address")
    print( " privkey", claim_prvkey )
    claim_pubkey = PublicKey.from_prvkey( claim_prvkey )
    claim_address = Address.from_pubkey( claim_pubkey )
    print( " address (cash)", claim_address.to_full_cash() )
    print( " address (legacy)", claim_address.to_legacy() )
    print( " address (hex)", claim_address.h.hex() )
    print()
    
    # Refund private key
    #  mainnet: L1MK6tz8mD9WRnr9RqsbDg9BYktUkUwd6ZWQRHgdHU1m6VbUPkdz
    #  testnet: cRiJZoyzCGqmbEKQpFgiazeFAzBtQw3KAbesXi98nafmMEgYAMDg
    # Refund address
    #  testnet: bchtest:qrref365h428zh4zvwpnnfzlp2tq4w9t8qnh0pzm5q
    #           myiEzYohqurvpghWrCaaafz5orGQinfEC9
    refund_secret = 0x7b42a6f4f75cb14d701965b9da9245940837b4b3d8073bd2cf228605c1f0fe40
    refund_prvkey = PrivateKey( refund_secret )
    print("Refund address")
    print( " privkey", refund_prvkey )
    refund_pubkey = PublicKey.from_prvkey( refund_prvkey )
    refund_address = Address.from_pubkey( refund_pubkey )
    print( " address (cash)", refund_address.to_full_cash() )
    print( " address (legacy)", refund_address.to_legacy() )
    print( " address (hex)", refund_address.h.hex() )
    print()
    print("---")
    print()
    
    ''' Absolute time lock '''
    print("ABSOLUTE TIME LOCK (nLocktime)")
    print()
    
    # Build contract address
    print("Absolute time lock contract address")
    locktime = 1270850
    redeemScript = simple_locktime_locking_script( locktime )
    print( " redeem script", redeemScript.hex() )
    contract_address = Address.from_script( redeemScript )
    print( " contract address (cash)", contract_address )
    print( " contract address (legacy)", contract_address.to_legacy() )
    print()
    
    # Build redeem transaction
    prevout_txid = "cd7d2d5d6e4cc7c15d35f57273bfe7e361216fc9c3732e26941be468d5553452"
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
    txin['pubkeys'] = []
    txin['nsigs'] = 0
    txin['redeem_script'] = redeemScript
    txin['unlocking_script'] = anyone_can_spend_unlocking_script() + push_data( redeemScript )
    
    output_value = (prevout_value - fee) // 2
    
    txout1 = {}
    txout1['address'] = output_address
    txout1['value'] = output_value
    txout1['type'] = 'p2pkh'
    
    # Another output in order to have a txsize > 100 bytes (rule from nov 15th)
    txout2 = {}
    txout2['address'] = output_address
    txout2['value'] = output_value
    txout2['type'] = 'p2pkh'
    
    tx = Transaction( 1, [txin], [txout1, txout2], locktime)
    print("Absolute time lock redeem transaction")
    print("Raw transaction", tx.serialize().hex())
    print("txid", tx.txid().hex())
    print("  Success ! (d82ee6122ff6431eccedf2c4524c1b62698703852001116f87f4506e57b83aad on bch testnet)")
    print()
    print("---")
    print()

    ''' Relative time lock '''
    print("RELATIVE TIME LOCK (nSequence)")
    print()
    
    # Build contract address for a 2-block time lock
    print("Relative 2-block time lock contract address")
    sequence = sequence_number(2, 'blocks')
    redeemScript = simple_sequence_locking_script( sequence )
    print( " redeem script", redeemScript.hex() )
    contract_address = Address.from_script( redeemScript )
    print( " contract address (cash)", contract_address )
    print( " contract address (legacy)", contract_address.to_legacy() )
    print()
    
    # Build redeem transaction
    prevout_txid = "c5c61bae1522a460053b4820b92830ddfadf9c34beef7a94287aff4e058026f7"
    prevout_index = 0
    prevout_value = 100000
    output_address = claim_address
    fee = 1000
    
    txin = {}
    txin['address'] = contract_address
    txin['txid'] = prevout_txid
    txin['index'] = prevout_index
    txin['value'] = prevout_value
    txin['sequence'] = sequence
    txin['pubkeys'] = []
    txin['nsigs'] = 0
    txin['redeem_script'] = redeemScript
    txin['unlocking_script'] = anyone_can_spend_unlocking_script() + push_data( redeemScript )
    
    output_value = (prevout_value - fee) // 2
    
    txout1 = {}
    txout1['address'] = output_address
    txout1['value'] = output_value
    txout1['type'] = 'p2pkh'
    
    # Another output in order to have a txsize > 100 bytes (rule from nov 15th)
    txout2 = {}
    txout2['address'] = output_address
    txout2['value'] = output_value
    txout2['type'] = 'p2pkh'
    
    tx = Transaction( Constants.TX_VERSION, [txin], [txout1, txout2], 0)
    print("Relative 2-block time lock redeem transaction")
    print("Raw transaction", tx.serialize().hex())
    print("txid", tx.txid().hex())
    print("  Success ! (e6a08d2b6ac7d6bd8a3e8900af5659178ed3b94de23375bbab81a31107556332 on bch testnet)")
    print()
    
    
    # Build contract address for a 512-second time lock
    print("Relative 512-second time lock contract address")
    sequence = sequence_number(512, 'seconds')
    redeemScript = simple_sequence_locking_script( sequence )
    print( " redeem script", redeemScript.hex() )
    contract_address = Address.from_script( redeemScript )
    print( " contract address (cash)", contract_address )
    print( " contract address (legacy)", contract_address.to_legacy() )
    print()
    
    # Build redeem transaction
    prevout_txid = "e564fd98282a8f46ea60ee63d96a3af1942d398963f1f0501f1084a82e1a1fd5"
    prevout_index = 1
    prevout_value = 100000
    output_address = claim_address
    fee = 1000
    
    txin = {}
    txin['address'] = contract_address
    txin['txid'] = prevout_txid
    txin['index'] = prevout_index
    txin['value'] = prevout_value
    txin['sequence'] = sequence
    txin['pubkeys'] = []
    txin['nsigs'] = 0
    txin['redeem_script'] = redeemScript
    txin['unlocking_script'] = anyone_can_spend_unlocking_script() + push_data( redeemScript )
    
    output_value = (prevout_value - fee) // 2
    
    txout1 = {}
    txout1['address'] = output_address
    txout1['value'] = output_value
    txout1['type'] = 'p2pkh'
    
    # Another output in order to have a txsize > 100 bytes (rule from nov 15th)
    txout2 = {}
    txout2['address'] = output_address
    txout2['value'] = output_value
    txout2['type'] = 'p2pkh'
    
    tx = Transaction( Constants.TX_VERSION, [txin], [txout1, txout2], 0)
    print("Relative 512-second time lock redeem transaction")
    print("Raw transaction", tx.serialize().hex())
    print("txid", tx.txid().hex())
    print("  Success ! (fafb6430344658d5903d63bf1707a041fb30fbab6d2a42718506380d566c3915 on bch testnet)")
    print()
    print("---")
    print()
    
    ''' Expiring tip. '''
    
    print("EXPIRING TIP")
    print()
    
    # Build contract address
    print("Expiring tip contract address")
    locktime = 1270964 # Block time lock
    redeemScript = expiring_tip_locking_script( locktime, claim_pubkey, refund_pubkey )
    print( " redeem script", redeemScript.hex() )
    contract_address = Address.from_script( redeemScript )
    print( " contract address (cash)", contract_address )
    print( " contract address (legacy)", contract_address.to_legacy() )
    print()
    
    # Build redeem transaction
    prevout_txid = "0eb24d00d4f828901652733aece87e3b5c402b34d8183e2f86f81e3edeabc9cf"
    prevout_index = 1
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
    
    tx = Transaction( Constants.TX_VERSION, [txin], [txout], locktime)
    tx.sign( [ refund_prvkey ] )
    print("Expiring tip refund transaction")
    print("Raw transaction", tx.serialize().hex())
    print("txid", tx.txid().hex())
    print("  Success (cd08fafbf1356007af79856ce122573bba169b4199bc49ed8eae8f06dc7c1fb6 on bch testnet)")
    print()
    
    print("seq", hex(sequence_number(86528, 'seconds')))
    