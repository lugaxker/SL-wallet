#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (sha256, hash160, PublicKey)
from address import Address
from nulldata import (create_memo_script, parse_memo_script)

from util import (read_bytes, push_data, read_data, op_number, read_op_number, script_number)

from constants import Constants

class ScriptError(Exception):
    '''Exception used for Script errors.'''

# Bitcoin script operation codes (op codes)
    
# Constants
OP_0 = OP_FALSE = 0x00      # 0
OP_1 = OP_TRUE = 0x51       # 1
OP_1NEGATE = 0x4f           # -1
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
    
# Flow control
OP_NOP = 0x61
OP_IF = 0x63
OP_NOTIF = 0x64
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_RETURN = 0x6a
  
# Stack
OP_TOALTSTACK = 0x6b
OP_FROMALTSTACK = 0x6c
OP_IFDUP = 0x73
OP_DEPTH = 0x74
OP_DROP = 0x75
OP_DUP = 0x76
OP_NIP = 0x77
OP_OVER = 0x78
OP_PICK = 0x79
OP_ROLL = 0x7a
OP_ROT = 0x7b
OP_SWAP = 0x7c
OP_TUCK = 0x7d
OP_2DROP = 0x6d
OP_2DUP = 0x6e
OP_3DUP = 0x6f
OP_2OVER = 0x70
OP_2ROT = 0x71
OP_2SWAP = 0x72

# Splice operations
OP_CAT = 0x7e
OP_SPLIT = 0x7f
#OP_SUBSTR = 0x7f replaced by OP_SPLIT in may 2018
OP_NUM2BIN = 0x80
#OP_LEFT = 0x80 replaced by OP_NUM2BIN in may 2018, can be implemented with varying combinations of OP_SPLIT, OP_SWAP and OP_DROP
OP_BIN2NUM = 0x81
#OP_RIGHT = 0x81 replaced by OP_BIN2NUM in may 2018, can be implemented with varying combinations of OP_SPLIT, OP_SWAP and OP_DROP
OP_SIZE = 0x82

# Bitwise logic
#OP_INVERT = 0x83 disabled: re-enabled in november 2019?
OP_AND = 0x84
OP_OR = 0x85
OP_XOR = 0x86
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88

# Arithmetic
OP_1ADD = 0x8b
OP_1SUB = 0x8c
OP_NEGATE = 0x8f
OP_ABS = 0x90
OP_NOT = 0x91
OP_0NOTEQUAL = 0x92
OP_ADD = 0x93
OP_SUB = 0x94
#OP_MUL = 0x95 disabled: re-enabled in november 2019?
OP_DIV = 0x96 
OP_MOD = 0x97 
#OP_LSHIFT = 0x98 disabled: re-enabled in november 2019?
#OP_RSHIFT = 0x99 disabled: re-enabled in november 2019?
 
# Crypto
OP_SHA1 = 0xa7
OP_SHA256 = 0xa8
OP_HASH160 = 0xa9
OP_CODESEPARATOR = 0xab
OP_CHECKSIG = 0xac
OP_CHECKSIGVERIFY = 0xad
OP_CHECKMULTISIG = 0xae
OP_CHECKMULTISIGVERIFY = 0xaf
OP_CHECKDATASIG = 0xba
OP_CHECKDATASIGVERIFY = 0xbb

# Locktime
OP_CHECKLOCKTIMEVERIFY = 0xb1
OP_CHECKSEQUENCEVERIFY = 0xb2

# Reserved words
OP_NOP1 = 0xb0 # previously reserved for OP_EVAL (BIP-12), an alternative to P2SH
OP_NOP4 = 0xb3
OP_NOP5 = 0xb4
OP_NOP6 = 0xb5
OP_NOP7 = 0xb6
OP_NOP8 = 0xb7
OP_NOP9 = 0xb8
OP_NOP10 = 0xb9

def multisig_locking_script(pubkeys, m):
    ''' Returns m-of-n multisig locking script (also called redeem script). '''
    n = len(pubkeys)
    if not 1 <= m <= n <= 3:
        raise ScriptError('{:d}-of-{:d} multisig script not possible'.format(m, n))
    OP_m = op_number( m )
    OP_n = op_number( n )
    serpubkeys = bytes().join( push_data( pubkey.to_ser() ) for pubkey in pubkeys)
    return ( bytes([OP_m]) + serpubkeys + bytes([OP_n, OP_CHECKMULTISIG]) )

def multisig_unlocking_script(sigs):
    ''' Returns m-of-n multisig unlocking script. '''
    return ( bytes([OP_0]) + b''.join(push_data(sig) for sig in sigs) )

def simple_locktime_locking_script( locktime ):
    ''' Simple anyone-can-spend CHECKLOCKTIMEVERIFY locking script. '''
    return ( push_data( script_number( locktime ) ) + 
             bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP]) )

def simple_sequence_locking_script( sequence ):
    ''' Simple anyone-can-spend CHECKSEQUENCEVERIFY locking script. '''
    assert not (sequence & Constants.SEQUENCE_LOCKTIME_DISABLE_FLAG)
    return ( push_data( script_number( sequence ) ) + 
             bytes([OP_CHECKSEQUENCEVERIFY, OP_DROP]) )

def anyone_can_spend_unlocking_script():
    ''' Anyone-can-spend unlocking script. '''
    return bytes([OP_TRUE])

def expiring_tip_locking_script( locktime, claim_pubkey, refund_pubkey ):
    assert (locktime < 0x100000000)
    assert isinstance( claim_pubkey, PublicKey )
    assert isinstance( refund_pubkey, PublicKey )
    assert (claim_pubkey.is_compressed() & refund_pubkey.is_compressed()), "public keys must be compressed"
    return ( bytes([OP_IF]) + 
             push_data( claim_pubkey.to_ser() ) +
             bytes([OP_ELSE]) + 
             push_data( script_number( locktime ) ) + 
             bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP]) + 
             push_data( refund_pubkey.to_ser() ) + 
             bytes([OP_ENDIF, OP_CHECKSIG]) )

def expiring_tip_unlocking_script( choice, sig ):
    assert isinstance( sig, (bytes, bytearray) ) 
    if choice == 'claim':
        return push_data( sig ) + bytes([OP_1])
    elif choice == 'refund':
        return push_data( sig ) + bytes([OP_0])
    else:
        raise ScriptError("wrong choice")


def locking_script( addr ):
    assert isinstance( addr, Address )
    if addr.kind == Constants.CASH_P2PKH:
        return (bytes([OP_DUP, OP_HASH160]) + 
            push_data( addr.h ) + 
            bytes([OP_EQUALVERIFY, OP_CHECKSIG]))
    elif addr.kind == Constants.CASH_P2SH:
        return (bytes([OP_HASH160]) + push_data( addr.h ) 
                + bytes([OP_EQUAL]))
    return None

def p2pkh_unlocking_script( addr, pubkeys, signatures ):
    assert isinstance( addr, Address )
    assert addr.kind == Constants.CASH_P2PKH
    assert isinstance( pubkeys[0], PublicKey )
    assert isinstance( signatures[0], (bytes, bytearray) ) 
    return (push_data( signatures[0] ) + push_data( pubkeys[0].to_ser() ))

def p2sh_unlocking_script( addr, redeem_script, pubkeys, signatures ):
    assert isinstance( addr, Address )
    assert addr.kind == Constants.CASH_P2SH
    assert isinstance( pubkeys[0], PublicKey )
    assert isinstance( signatures[0], (bytes, bytearray) ) 
    assert isinstance( redeem_script, (bytes, bytearray) )
    assert hash160(redeem_script) == addr.h
    # TODO: parse script
    
    if redeem_script[-1] == OP_CHECKMULTISIG:
        # Multisig output to unlock
        assert redeem_script == multisig_locking_script(pubkeys, len(signatures))
        return (multisig_unlocking_script(signatures) 
                + push_data( redeem_script ))
    
    elif (len(redeem_script) in [75,76,77,78,79,80]) & (redeem_script[-38] == OP_CHECKLOCKTIMEVERIFY):
        # Expiring tip
        choice = 'refund'
        print("expiring tip: {} !".format(choice))
        return ( expiring_tip_unlocking_script( 'refund', signatures[0])
                    + push_data( redeem_script ) )
        
    else:
        raise ScriptError("cannot parse script")
    
def nulldata_script( data ):
    ''' Data (temporary: int, bytes and str) '''
    
    script = bytes([OP_RETURN])
    for d in data:
        if isinstance(d, int):
            script += push_data( script_number(d) )
        elif isinstance(d, bytes):
            script += push_data( d )
        elif isinstance(d, str):
            script += push_data( d.encode('utf-8') )
        else:
            NullDataError("cannot serialize nulldata script")
            
    return script
    
    

# TODO: create memo.py and matter.py

DATA_MEMO = 0x6d
DATA_MATTER = 0x9d
DATA_BLOCKPRESS = 0x8d

# TODO



#def nulldata_script( data ):
    #''' Data (temporary: int, bytes and str) '''
    
    #for i, d in enumerate(data):
        #if isinstance(d, Address):
            #data[i] = d.h
        #elif isinstance(d, PublicKey):
            #data[i] = d.to_ser(strtype=False)
    
    #script = bytes([OP_RETURN])
    #for d in data:
        #if isinstance(d, int):
            #script += push_data( script_number(d) )
        #elif isinstance(d, bytes):
            #script += push_data( d )
        #elif isinstance(d, str):
            #script += push_data( d.encode('utf-8') )
        #else:
            #ScriptError("cannot serialize nulldata script")
            
    #return script
            
            
    #if prefix is None:
        #return bytes().join( push_data(d) for d in content )
    #elif 0x6d00 <= prefix <= 0x6dff: # memo
        #return bytes([OP_RETURN]) + create_memo_script(prefix, content)
    #elif 0x9d00 <= prefix <= 0x9dff: # matter 
        #script = bytes([OP_RETURN]) + push_data( prefix.to_bytes(2, 'big') )
        ####
        #if prefix in (0x9d03, 0x9d04, 0x9d05): # profile name, picture, bio
            #return ( script +
                #bytes().join( push_data( d.encode('utf-8') ) for d in content ) )
        #elif prefix in (0x9d01, 0x9d02, 0x9d07, 0x9d08): # header and chunk for post and comment
            #return (script + push_data( bytes.fromhex( content[0] ) ) + 
                    #push_data( bytes([content[1]]) ) +
                    #bytes().join( push_data( d.encode('utf-8') ) for d in content[2:] ) )
        #else:
            #raise ScriptError("cannot serialize data script")
        
    #else:
        #raise ScriptError("cannot serialize data script")
    
    
def read_nulldata_script( script ):
    ''' Read nulldata script content. '''
    assert len(script) <= 223
    ret, script = read_bytes( script, 1, int, 'big' )
    assert ret == OP_RETURN
    
    data = []
    while script != bytes():
        d, script = read_data( script )
        data.append( d )
    return data
    
#def parse_nulldata_script( script ):    
    #ret, script = read_bytes( script, 1, int, 'little' )
    #assert ret == OP_RETURN
    #assert len(script) <= 220
    #protocol = {DATA_MEMO: "memo", DATA_MATTER: "matter"}[script[1]]
    #if protocol == "memo":
        #prefix, content = parse_memo_script( script )
        #return content, prefix
    #elif protocol == "matter": 
        #if prefix == 0x01: # post header
            #checksum, script = read_data( script )
            #chunkCount, script = read_data( script )
            #chunk_count = int.from_bytes( chunkCount, 'little' )
            #if script != bytes():
                #title, script = read_data( script )
            
            #content = [ checksum.hex(), chunk_count, title.decode('utf-8') ]
            #while script != bytes():
                #tag, script = read_data( script )
                #content.append( tag )
            #return content, prefix
        #elif prefix == 0x02: # post chunk
            #headerTxId, script = read_data( script )
            #header_txid = headerTxId.hex()
            #chunkId, script = read_data( script ) 
            #chunk_id = int.from_bytes( chunkId, 'little' )
            #text, script = read_data( script )            
            #return [header_txid, chunk_id, text.decode('utf-8')], prefix
        #elif prefix == 0x03: # set profile name
            #name, script = read_data( script )
            #return [name.decode('utf-8')], prefix
        #elif prefix == 0x04: # set profile picture
            #url, script = read_data( script )
            #return [url.decode('utf-8')], prefix
        #elif prefix == 0x05: # set profile bio
            #bio, script = read_data( script )
            #return [bio.decode('utf-8')], prefix
        #elif prefix == 0x07: # comment header
            #checksum, script = read_data( script )
            #chunkCount, script = read_data( script )
            #chunk_count = int.from_bytes( chunkCount, 'little' )
            
            #content = [ checksum.hex(), chunk_count ]
            #if (chunk_count == 0) & (script != bytes()):
                #text, script = read_data( script )
                #content.append( text )
            #return content, prefix
        #elif prefix == 0x08: # comment chunk
            #headerTxId, script = read_data( script )
            #header_txid = headerTxId.hex()
            #chunkId, script = read_data( script ) 
            #chunk_id = int.from_bytes( chunkId, 'little' )
            #text, script = read_data( script )            
            #return [header_txid, chunk_id, text.decode('utf-8')], prefix
        #else:
            #content = []
            #while script != bytes():
                #d, script = read_data( script )
                #content.append( d )
            #return content, None
    #else:
        #content = []
        #while script != bytes():
            #d, script = read_data( script )
            #content.append( d )
        #return content, None
    

def parse_unlocking_script( script ):
    # Returns type, signatures, public keys and address of the input
    if len( script ) in [71, 72, 73]:
        # Pay-to-Public-Key: the unlocking script is the signature
        sig, script = read_data( script )
        assert script == bytes()
        return "p2pk", [sig], None, None, None
    elif len( script ) in [105, 106, 107, 137, 138, 139]: #P2PKH
        # Pay-to-Public-Key-Hash: signature and public key
        sig, script = read_data( script )
        pubkey, script = read_data( script )
        assert script == bytes()
        return "p2pkh", [sig], [ PublicKey.from_ser( pubkey ) ], Address.from_pubkey( pubkey ), None
    elif script[0] == OP_0:
        # P2SH multisig
        zero, script = read_bytes( script, 1, int, 'little')
        data = []
        while script != bytes():
            d, script = read_data( script )
            data.append( d )
        signatures, redeemScript = data[:-1], data[-1]
        
        # Address
        address = Address.from_script( redeemScript )
        
        rs = redeemScript
        # Parsing of redeem script
        m, rs = read_bytes( rs, 1, int, 'little')
        assert len(signatures) == (m - OP_1 + 1), "m = {:d}, len sigs = {:d}".format(m, len(signatures))
        pubkeys = []
        while 0 < rs[0] <= OP_PUSHDATA4:
            pubkey, rs = read_data( rs )
            pubkeys.append( PublicKey.from_ser( pubkey ) )
        n, rs = read_bytes( rs, 1, int, 'little')
        assert len(pubkeys) == (n - OP_1 + 1)
        assert rs[0] == OP_CHECKMULTISIG
        
        return "p2sh", signatures, pubkeys, address, redeemScript
    else:
        raise ScriptError("cannot parse unlocking script")

def parse_locking_script( script ):
    # Returns type and address
    if (script[-1] == OP_CHECKSIG) & (len(script) in [35, 67]):
        # Pay-to-Public-Key
        pubkey, _ = read_data( script )
        return "p2pk", Address.from_pubkey( pubkey ), None
    elif ((script[0] == OP_DUP) & (script[1] == OP_HASH160) & 
          (script[-2] == OP_EQUALVERIFY) & (script[-1] == OP_CHECKSIG)
          & (len(script) == 25)):
        # Pay-to-Public-Key-Hash
        h, _ = read_data( script[2:-2] )
        return "p2pkh", Address.from_pubkey_hash( h ), None
    elif ((script[0] == OP_HASH160) & (script[-1] == OP_EQUAL) & (len(script) == 23)):
        # Pay-to-Script-Hash
        h, _ = read_data( script[1:-1] )
        return "p2sh", Address.from_script_hash( h ), None
    elif (script[0] == OP_RETURN) & (len(script) <= 223):
        address = "d-" + sha256( script.hex().encode('utf-8') )[:16].hex()
        data = read_nulldata_script( script )
        return "nulldata", address, data
    else:
        raise ScriptError("cannot parse locking script")

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    print("SHA-1 collision bounty")
    script = bytes( [OP_2DUP, OP_EQUAL, OP_NOT, OP_VERIFY, OP_SHA1, OP_SWAP, OP_SHA1, OP_EQUAL] )
    address = Address.from_script( script )
    print("script", script.hex() )
    print("address", address.to_legacy() )
    
    script = bytes( [op_number(3), OP_ADD, op_number(5), OP_EQUAL] )
    address = Address.from_script( script )
    print("script", script.hex() )
    print("address", address.to_legacy() )
    print("hash", address.h.hex() )
    
    # 
    
    # P2MS address
    script = "5121032df7cde5c76b9d8dc36317c74952cc3fdc6d0afb30580ea3b63394497469d47a51ae"
    address = "m-" + sha256( script.encode('utf-8') )[:16].hex()
    print("script", script)
    print("P2MS address", address)