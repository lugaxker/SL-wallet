#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (sha256, hash160, PublicKey)
from address import Address

from util import read_bytes

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
OP_DROP = 0x75
OP_DUP = 0x76
OP_SWAP = 0x7c

# Bitwise logic
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
 
# Crypto
OP_HASH160 = 0xa9
OP_CHECKSIG = 0xac
OP_CHECKMULTISIG = 0xae

# Locktime
OP_CHECKLOCKTIMEVERIFY = 0xb1
OP_CHECKSEQUENCEVERIFY = 0xb2

def op_number( n ):
    '''Returns the corresponding op code for a number: from OP_0 to OP_16. '''
    assert (0x00 <= n <= 0x10)
    return (OP_1 + n - 1) if n != 0 else OP_0

def read_op_number( n ):
    assert (n == 0) | (OP_1 <= n <= 0x60)
    return (n - OP_1 + 1) if n != 0 else 0

def push_data(data):
    '''Returns the op codes to push the data on the stack.'''
        
    # data must be a bytes string
    assert isinstance(data, (bytes, bytearray))

    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xff:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xffff:
        return bytes([OP_PUSHDATA2]) + n.to_bytes(2, 'little') + data
    if n <= 0xffffffff:
        return bytes([OP_PUSHDATA4]) + n.to_bytes(4, 'little') + data
    else:
        raise ValueError("Data is too long")
    
def push_data_size(n):
    OP_PUSHDATA1 = 0x4c
    if n < OP_PUSHDATA1:
        return 1
    elif n <= 0xff:
        return 2
    elif n <= 0xffff:
        return 3
    elif n <= 0xffffffff:
        return 5
    else:
        raise ValueError("Data is too long")
    
def read_data( b ):
    if b[0] < OP_PUSHDATA1:
        n, b = read_bytes( b, 1, int, 'little')
    elif b[0] == OP_PUSHDATA1:
        n, b = read_bytes( b[1:], 1, int, 'little') 
    elif b[0] == OP_PUSHDATA2:
        n, b = read_bytes( b[1:], 2, int, 'little') 
    elif b[0] == OP_PUSHDATA4:
        n, b = read_bytes( b[1:], 4, int, 'little')
    else:
        raise ValueError("cannot read data")
    return read_bytes( b, n, bytes, 'big') 
    
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

def unlocking_script( addr, pubkeys, signatures ):
    assert isinstance( addr, Address )
    assert isinstance( pubkeys[0], PublicKey )
    assert isinstance( signatures[0], (bytes, bytearray) ) 
    if addr.kind == Constants.CASH_P2PKH:
        sig = signatures[0]
        pubkey = pubkeys[0]
        assert addr == Address.from_pubkey( pubkey )
        return (push_data( sig ) + push_data( pubkey.to_ser() ))
    elif addr.kind == Constants.CASH_P2SH:
        redeemScript = multisig_locking_script(pubkeys, len(signatures))
        assert addr.h == hash160(redeemScript) 
        return (multisig_unlocking_script(signatures) 
                + push_data( redeemScript ))
    
DATA_MEMO = 0x6d
DATA_MATTER = 0x9d
DATA_BLOCKPRESS = 0x8d

def return_script( content, prefix=None, protocol=None ):
    ''' Content (list of str) '''
    for i, d in enumerate(content):
        if isinstance(d, Address):
            content[i] = d.h.hex()
            
    assert all( isinstance(d, (str, int)) for d in content)
    
    if protocol is None:
        if prefix is None:
            script = bytes().join( push_data(d) for d in content )
        else:
            script = push_data( prefix ) + bytes().join( push_data(d) for d in content )
    elif protocol == "memo":
        script = bytes([OP_RETURN]) + push_data( bytes([DATA_MEMO, prefix]) )
        
        if prefix in (0x01, 0x02, 0x05, 0x0a, 0x0c, 0x0d, 0x0e):
            return( script +
                bytes().join( push_data( d.encode('utf-8') ) for d in content ) )
        elif prefix in (0x03, 0x04, 0x06, 0x07):
            return( script +
                    push_data( bytes.fromhex( content[0] ) ) +
                    bytes().join( push_data( d.encode('utf-8') ) for d in content[1:] ) )
        elif prefix == 0x10: # Poll
            poll_type = op_number( content[0] )
            option_count = op_number( content[1] ) 
            return ( script + bytes( [poll_type, option_count] ) +
                     bytes().join( push_data( d.encode('utf-8') ) for d in content[2:] ) )
        elif prefix in (0x13, 0x14): # Poll option, poll vote
            return( script + push_data( bytes.fromhex( content[0] )[::-1] ) +
                    bytes().join( push_data( d.encode('utf-8') ) for d in content[1:] ) )
            
        else:
            raise ScriptError("cannot serialize data script")
    elif protocol == "matter": 
        script = bytes([OP_RETURN]) + push_data( bytes([DATA_MATTER, prefix]) )
        ###
        if prefix in (0x03, 0x04, 0x05): # profile name, picture, bio
            return ( script +
                bytes().join( push_data( d.encode('utf-8') ) for d in content ) )
        elif prefix in (0x01, 0x02, 0x07, 0x08): # header and chunk for post and comment
            return (script + push_data( bytes.fromhex( content[0] ) ) + 
                    push_data( bytes([content[1]]) ) +
                    bytes().join( push_data( d.encode('utf-8') ) for d in content[2:] ) )
        else:
            raise ScriptError("cannot serialize data script")
        
    else:
        raise ScriptError("cannot serialize data script")
    
    
def parse_return_script( script ):
    ''' Returns protocol, prefix and content. '''
    ret, script = read_bytes( script, 1, int, 'little' )
    assert len(script) <= 220
    meta, script = read_data( script )
    protocol = {DATA_MEMO: "memo", DATA_MATTER: "matter"}[meta[0]]
    prefix = meta[1]
    if protocol == "memo": 
        if prefix == 0x01: # set name
            name, script = read_data( script )
            return [name.decode('utf-8')], prefix, protocol
        elif prefix == 0x02: # post
            post, script = read_data( script )
            return [post.decode('utf-8')], prefix, protocol
        elif prefix == 0x03: # reply
            txhash, script = read_data( script )
            reply, script = read_data( script )
            return [txhash[::-1].hex(), reply.decode('utf-8')], prefix, protocol
        elif prefix == 0x04: # like
            txhash, script = read_data( script )
            return [txhash[::-1].hex()], prefix, protocol
        elif prefix == 0x05: # set profile text
            profile, script = read_data( script )
            return [profile.decode('utf-8')], prefix, protocol
        elif prefix == 0x06: # follow 
            address, script = read_data( script )
            return [Address.from_pubkey_hash( address )], prefix, protocol
        elif prefix == 0x07: # unfollow
            address, script = read_data( script )
            return [Address.from_pubkey_hash( address )], prefix, protocol
        elif prefix == 0x0a: # set profile picture
            url, script = read_data( script )
            return [url.decode('utf-8')], prefix, protocol
        elif prefix == 0x0c: # topic post
            topic, script = read_data( script )
            post, script = read_data( script )
            return [topic.decode('utf-8'), post.decode('utf-8')], prefix, protocol
        elif prefix == 0x0d: # topic follow 
            topic, script = read_data( script )
            return [topic], prefix, protocol
        elif prefix == 0x0e: # topic unfollow 
            topic, script = read_data( script )
            return [topic], prefix, protocol
        elif prefix == 0x10: # poll
            poll_type = read_op_number( script[0] )
            option_count = read_op_number( script[1] )
            question, script = read_data( script[2:] )
            return [poll_type, option_count, question.decode('utf-8')], prefix, protocol
        elif prefix == 0x13: # poll option
            txhash, script = read_data( script )
            option, script = read_data( script )
            return [txhash[::-1].hex(), option.decode('utf-8')], prefix, protocol
        elif prefix == 0x14: # poll vote
            txhash, script = read_data( script )
            comment, script = read_data( script )
            return [txhash[::-1].hex(), comment.decode('utf-8')], prefix, protocol
        else:
            content = []
            while script != bytes():
                d, script = read_data( script )
                content.append( d )
            return content, None, protocol
    elif protocol == "matter": 
        if prefix == 0x01: # post header
            checksum, script = read_data( script )
            chunkCount, script = read_data( script )
            chunk_count = int.from_bytes( chunkCount, 'little' )
            if script != bytes():
                title, script = read_data( script )
            
            content = [ checksum.hex(), chunk_count, title.decode('utf-8') ]
            while script != bytes():
                tag, script = read_data( script )
                content.append( tag )
            return content, prefix, protocol
        elif prefix == 0x02: # post chunk
            headerTxId, script = read_data( script )
            header_txid = headerTxId.hex()
            chunkId, script = read_data( script ) 
            chunk_id = int.from_bytes( chunkId, 'little' )
            text, script = read_data( script )            
            return [header_txid, chunk_id, text.decode('utf-8')], prefix, protocol
        elif prefix == 0x03: # set profile name
            name, script = read_data( script )
            return [name.decode('utf-8')], prefix, protocol
        elif prefix == 0x04: # set profile picture
            url, script = read_data( script )
            return [url.decode('utf-8')], prefix, protocol
        elif prefix == 0x05: # set profile bio
            bio, script = read_data( script )
            return [bio.decode('utf-8')], prefix, protocol
        elif prefix == 0x07: # comment header
            checksum, script = read_data( script )
            chunkCount, script = read_data( script )
            chunk_count = int.from_bytes( chunkCount, 'little' )
            
            content = [ checksum.hex(), chunk_count ]
            if (chunk_count == 0) & (script != bytes()):
                text, script = read_data( script )
                content.append( text )
            return content, prefix, protocol
        elif prefix == 0x08: # comment chunk
            headerTxId, script = read_data( script )
            header_txid = headerTxId.hex()
            chunkId, script = read_data( script ) 
            chunk_id = int.from_bytes( chunkId, 'little' )
            text, script = read_data( script )            
            return [header_txid, chunk_id, text.decode('utf-8')], prefix, protocol
        else:
            content = []
            while script != bytes():
                d, script = read_data( script )
                content.append( d )
            return content, None, protocol
    else:
        content = []
        while script != bytes():
            d, script = read_data( script )
            content.append( d )
        return content, None, None
    

def parse_unlocking_script( script ):
    # Returns type, signatures, public keys and address of the input
    if len( script ) in [71, 72, 73]:
        # Pay-to-Public-Key: the unlocking script is the signature
        sig, script = read_data( script )
        assert script == bytes()
        return "p2pk", [sig], None, None
    elif len( script ) in [105, 106, 107, 137, 138, 139]: #P2PKH
        # Pay-to-Public-Key-Hash: signature and public key
        sig, script = read_data( script )
        pubkey, script = read_data( script )
        assert script == bytes()
        return "p2pkh", [sig], [ PublicKey.from_ser( pubkey ) ], Address.from_pubkey( pubkey )
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
        
        # Parsing of redeem script
        m, redeemScript = read_bytes( redeemScript, 1, int, 'little')
        assert len(signatures) == (m - OP_1 + 1), "m = {:d}, len sigs = {:d}".format(m, len(signatures))
        pubkeys = []
        while 0 < redeemScript[0] <= OP_PUSHDATA4:
            pubkey, redeemScript = read_data( redeemScript )
            pubkeys.append( PublicKey.from_ser( pubkey ) )
        n, redeemScript = read_bytes( redeemScript, 1, int, 'little')
        assert len(pubkeys) == (n - OP_1 + 1)
        assert redeemScript[0] == OP_CHECKMULTISIG
        
        return "p2sh", signatures, pubkeys, address
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
    elif (script[0] == OP_RETURN) & (len(script) <= 221):
        address = "d-" + sha256( script.hex().encode('utf-8') )[:16].hex()
        content, prefix, protocol = parse_return_script( script )
        return "nulldata", address, [content, prefix, protocol]
    else:
        raise ScriptError("cannot parse locking script")

    
    
    
