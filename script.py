#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from address import Address

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
OP_HASH160= 0xa9
OP_CHECKSIG = 0xac

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
    
def locking_script_from_address( addr ):
    assert isinstance( addr, Address )
    if addr.kind == Address.ADDR_P2PKH:
        return (bytes([OP_DUP, OP_HASH160]) + 
            push_data( addr.hash_addr ) + 
            bytes([OP_EQUALVERIFY, OP_CHECKSIG]))
    return None

def unlocking_script( publicKey, signature ):
    assert isinstance( publicKey, (bytes, bytearray) )
    assert isinstance( signature, (bytes, bytearray) )
    return (push_data( signature ) + push_data( publicKey ))
    
    
