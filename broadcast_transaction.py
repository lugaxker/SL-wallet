#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib

from address import *
from crypto import (sha256, double_sha256, hash160, EllipticCurveKey)

SIGHASH_ALL = 0x01
SIGHASH_FORKID = 0x40
BCH_SIGHASH_TYPE = 0x41

def construct_transaction( wifkey, receive_address, amount, locktime ):
    ''' Construct a Bitcoin Cash transaction.
    wifkey (str) : private key (Wallet Import Format)
    receive_address (str) : recipient address (legacy or cash format)
    amount (int) : amount in satoshis '''
    
    # Creation of elliptic curve keys (private key + public key)
    eckey = EllipticCurveKey.from_wifkey( wifkey )
    
    # Public key and address (Public Key Hash)
    K = eckey.serialized_pubkey()
    print("Public key", K.hex())
    sendaddr = Address.from_pubkey( K )
    print("Sending address", sendaddr.to_cash())
    print("Sending address (Public Key Hash)", sendaddr.hash_addr.hex())
    recaddr = Address.from_string( receive_address )
    print("Receiving address", recaddr.to_cash())
    print("Receiving address (Public Key Hash)", recaddr.hash_addr.hex())
    print()
    
    version = 1
    nVersion = version.to_bytes(4,'little')
    print("version", nVersion.hex())
    
    hashtype = BCH_SIGHASH_TYPE
    nHashtype = hashtype.to_bytes(4,'little')
    print("signature hash type", nHashtype.hex())
    
    sequence = 0xffffffff - 1
    nSequence = sequence.to_bytes(4,'little')
    print("sequence number",nSequence.hex())
    
    nAmount = amount.to_bytes(4,'little')
    print("amount", nAmount.hex())
    
    nLocktime = locktime.to_bytes(4,'little')
    print("locktime", nLocktime.hex())
    
    print()
    
    
    # Steps
    # - Construct preimage (temporary transaction)
    # - Construct unlocking script
    # - Construct transaction
    
    ####################################################################################
    
    # https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
    # for transaction 0dcae2fe53e894773a457403e27bfacba38a31cde99647e24b3e805f1cb984d3
    
    eckey_0 = EllipticCurveKey( bytes.fromhex("a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e") )
    assert eckey_0.secret == 0xa0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e
    
    # Step 1 to 14
    temp_tx_0 = "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2010000001976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac0000000001000000"
    temp_tx_hash_0 = double_sha256( bytes.fromhex(temp_tx_0) )
    assert temp_tx_hash_0.hex() == "9302bda273a887cb40c13e02a50b4071a31fd3aae3ae04021b0b843dd61ad18e"
    print("Temporary transaction hash", temp_tx_hash_0.hex())
    
    # Step 15
    signature_0 = eckey_0.sign(temp_tx_hash_0)
    signature_0 += bytes([SIGHASH_ALL])
    print("signature + SIGHASH_ALL", signature_0.hex(), len(signature_0))
    K_0 = eckey_0.serialized_pubkey()
    print("Public key", K_0.hex())
    
    # Step 16
    # scriptSig: <One-byte script OPCODE containing the length of the DER-encoded signature plus 1 (the length of the one-byte hash code type)>|< The actual DER-encoded signature plus the one-byte hash code type>|< One-byte script OPCODE containing the length of the public key>|<The actual public key>
    # <One-byte script OPCODE containing the length of the DER-encoded signature plus 1 (the length of the one-byte hash code type)>
    scriptSig = bytes([len(signature_0)])
    
    # < The actual DER-encoded signature plus the one-byte hash code type>
    scriptSig += signature_0
    
    # < One-byte script OPCODE containing the length of the public key>
    scriptSig += bytes([len(K_0)])
    
    # <The actual public key>
    scriptSig += K_0
    
    print("* scriptSig", scriptSig.hex())

    # Steps 17-18
    tx_0 =  bytes.fromhex("0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f201000000")
    tx_0 += bytes([len(scriptSig)])
    tx_0 += scriptSig
    tx_0 += bytes.fromhex("ffffffff01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac00000000")
    print("* Transation", tx_0.hex())
    
    tx_id_0 = double_sha256( tx_0 )
    print("* Transaction ID", tx_id_0.hex() )
    
    print()
    
    tx_2 = bytes.fromhex( "0100000001bda694b9278473b080c97a37c5210aa7c87f80417d229ab5efc03f9c9909f5f5010000008a47304402202f514be883b1e362af04122b32c78d6016c2af86b49213ad0d6aba1da12519d202203bd4a346c367bdcdfedb65244a1bfc619ab87955aeffd512a8f26b920b93ed3f414104bd04eb432f9844f54d2c1e6fe328f7bf13f41bfbd49fa5515ecc27a2e651d4b87d0e8022eb0a6b0bf637aa4a18d54e181849841313a4f05c26abed7fd352c5bffeffffff0130260000000000001976a9143dc1c74269f805380c7eff955ae272fc5e64ab2588ac0ff40700" )
    tx_id_2 = double_sha256( tx_2 )
    print("* Transaction ID", tx_id_2[::-1].hex() )
    
    print()
    
    # Our own transaction
    print("- Our own transaction")
    print()
    # Step 1 to 13
    temporary_tx_str =  "01000000" # version
    temporary_tx_str += "01" # input count
    temporary_tx_str += "bda694b9278473b080c97a37c5210aa7c87f80417d229ab5efc03f9c9909f5f5" # previous transaction id
    temporary_tx_str += "01000000" # previous output index
    # temporarily filled with the scriptPubKey of the output we want to redeem
    temporary_tx_str += "19" # length of previous scriptPubKey
    temporary_tx_str += "76a91497982cc1e24683fa9ed357c10b83f8a28f6021a988ac" # previous scriptPubKey
    temporary_tx_str += "feffffff" # sequence number
    temporary_tx_str += "01" # number ou outputs
    temporary_tx_str += "3026000000000000" # value
    temporary_tx_str += "19" # length of scriptPubKey
    temporary_tx_str += "76a9143dc1c74269f805380c7eff955ae272fc5e64ab2588ac" # scriptPubKey
    temporary_tx_str += "0ff40700"
    temporary_tx_str += "41000000" # sighash type
    
    # Step 14
    temp_tx_hash_1 = double_sha256( bytes.fromhex( temporary_tx_str ) )
    print("Temporary transaction hash", temp_tx_hash_1.hex() )
    
    # Step 15
    signature_1 = eckey.sign(temp_tx_hash_1)
    signature_1 += bytes([BCH_SIGHASH_TYPE])
    print("signature + SIGHASH_TYPE", signature_1.hex())
    
    tx = b""
    
    return tx
    
    
if __name__ == '__main__':
    print()
    print("BROADCAST TRANSACTION")
    print("---------------------")
    print()
    
    wifkey = "5KLnc4W67hQ2NYPky89WJYmEGfh42ddkui9YL7px9EnJq3KA6KE"
    recipient_address = "bitcoincash:qq7ur36zd8uq2wqv0mle2khzwt79ue9ty57mvd95r0"
    amount = 50000
    locktime = 0
    tx = construct_transaction( wifkey, recipient_address, amount, locktime )
    
    print()
