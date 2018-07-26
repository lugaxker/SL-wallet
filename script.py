#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import hash160
from address import Address

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
    
def multisig_locking_script(pubkeys, m):
    ''' Returns m-of-n multisig locking script (also called redeem script). '''
    n = len(pubkeys)
    if not 1 <= m <= n <= 3:
        raise ScriptError('{:d}-of-{:d} multisig script not possible'.format(m, n))
    OP_m = OP_1 + m - 1
    OP_n = OP_1 + n - 1
    serpubkeys = b''.join(push_data(pubkey) for pubkey in pubkeys)
    return ( bytes([OP_m]) + serpubkeys + bytes([OP_n, OP_CHECKMULTISIG]) )

def multisig_unlocking_script(sigs):
    ''' Returns m-of-n multisig unlocking script. '''
    return ( bytes([OP_0]) + b''.join(push_data(sig) for sig in sigs) )

def locking_script( addr ):
    assert isinstance( addr, Address )
    if addr.kind == Address.ADDR_P2PKH:
        return (bytes([OP_DUP, OP_HASH160]) + 
            push_data( addr.h ) + 
            bytes([OP_EQUALVERIFY, OP_CHECKSIG]))
    elif addr.kind == Address.ADDR_P2SH:
        return (bytes([OP_HASH160]) + push_data( addr.h ) 
                + bytes([OP_EQUAL]))
    return None

def unlocking_script( addr, pubkeys, signatures ):
    assert isinstance( addr, Address )
    assert isinstance( pubkeys[0], (bytes, bytearray)  )
    assert isinstance( signatures[0], (bytes, bytearray) ) 
    if addr.kind == Address.ADDR_P2PKH:
        sig = signatures[0]
        pubkey = pubkeys[0]
        assert addr.h == hash160(pubkey) 
        return (push_data( sig ) + push_data( pubkey ))
    elif addr.kind == Address.ADDR_P2SH:
        redeemScript = multisig_locking_script(pubkeys, len(signatures))
        assert addr.h == hash160(redeemScript) 
        return (multisig_unlocking_script(signatures) 
                + push_data( redeemScript ))


    
    
    
