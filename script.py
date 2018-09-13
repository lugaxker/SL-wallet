#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import (hash160, PublicKey)
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
OP_DUP = 0x76

# Bitwise logic
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
 
# Crypto
OP_HASH160 = 0xa9
OP_CHECKSIG = 0xac
OP_CHECKMULTISIG = 0xae

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
    OP_m = OP_1 + m - 1
    OP_n = OP_1 + n - 1
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
    else:
        raise ScriptError("cannot parse unlocking script")

        return "p2sh", signatures, pubkeys, address

def parse_locking_script( script ):
    # Returns type and address
    if len(script) in [35, 67]:
        # Pay-to-Public-Key
        pubkey, script = read_data( script )
        assert (len(script) == 1) & (script[0] == OP_CHECKSIG)
        return "p2pk", Address.from_pubkey( pubkey )
    elif len(script) == 25:
        # Pay-to-Public-Key-Hash
        assert ((script[0] == OP_DUP) & (script[1] == OP_HASH160) & 
                (script[-2] == OP_EQUALVERIFY) & (script[-1] == OP_CHECKSIG))
        h, _ = read_data( script[2:-2] )
        return "p2pkh", Address.from_pubkey_hash( h )
    elif len(script) == 23:
        # Pay-to-Script-Hash
        assert (script[0] == OP_HASH160) & (script[-1] == OP_EQUAL)
        h, _ = read_data( script[1:-1] )
        return "p2sh", Address.from_script_hash( h )
    else:
        raise ScriptError("cannot parse unlocking script")

    
    
    
