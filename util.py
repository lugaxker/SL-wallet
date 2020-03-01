#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Bytes

def read_bytes( b, l, t, e ):
    if t == bytes:
        if e == 'big':
            return b[:l], b[l:]
        if e == 'little':
            return b[l::-1], b[l:]
    elif t == hex:
        if e == 'big':
            return b[:l].hex(), b[l:]
        if e == 'little':
            return b[(l-1)::-1].hex(), b[l:]
    elif t == int:
        return int.from_bytes( b[:l], e ), b[l:]
    return None

def var_int(i):
    '''Returns variable length integer used in the transaction payload.'''
    if i < 0xfd:
        return bytes([i])
    elif i <= 0xffff:
        return bytes([0xfd]) + i.to_bytes(2, 'little')
    elif i <= 0xffffffff:
        return bytes([0xfe]) + i.to_bytes(4, 'little')
    elif i <= 0xffffffffffffffff:
        return bytes([0xff]) + i.to_bytes(8, 'little')
    else:
        raise ValueError("Integer is too big")
    
def read_var_int(b):
    if b[0] < 0xfd:
        return b[0], b[1:]
    elif b[0] == 0xfd:
        return int.from_bytes( b[1:3], 'little' ), b[3:]
    elif b[0] == 0xfe:
        return int.from_bytes( b[1:5], 'little' ), b[5:]
    elif b[0] == 0xff:
        return int.from_bytes( b[1:9], 'little' ), b[9:]
    else:
        raise ValueError("Cannot parse integer")

def var_int_size(i):
    if i < 0xfd:
        return 1
    elif i <= 0xffff:
        return 3
    elif i <= 0xffffffff:
        return 5
    elif i <= 0xffffffffffffffff:
        return 9
    else:
        raise ValueError("Integer is too big")
    
OP_0 = 0x00
OP_1 = 0x51

def op_number( n ):
    '''Returns the corresponding op code for a number: from OP_0 to OP_16. '''
    assert (0x00 <= n <= 0x10)
    return (OP_1 + n - 1) if n != 0 else OP_0

def read_op_number( n ):
    assert (n == 0) | (OP_1 <= n <= 0x60)
    return (n - OP_1 + 1) if n != 0 else 0
    
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_1NEGATE = 0x4f

def push_data(data):
    '''Returns the op codes to push the data on the stack.'''
        
    # data must be a bytes string
    assert isinstance(data, (bytes, bytearray))

    # Minimal push must be enforced (HF-20191511)
    n = len(data)
    if n == 0:
        return bytes([OP_0])
    if n == 1 & (0x01 <= int.from_bytes(data, 'big') <= 0x10):
        return bytes([op_number( int.from_bytes(data, 'big') )])
    if n == 1 & (int.from_bytes(data, 'big') == 0x81):
        return OP_1NEGATE
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
    elif (b[0] == 0) | (OP_1 <= b[0] <= 0x60):
        n, b = read_op_number( b[0] ), b[1:]
    else:
        raise ValueError("cannot read data")
    return read_bytes( b, n, bytes, 'big') 

def script_number( n ):
    ''' Positive script number. '''
    if ( 0x80000000 <= n < 0x100000000 ):
        # Only for absolute locktime
        return n.to_bytes(5, 'little')
    elif ( 0x800000 <= n < 0x80000000 ):
        return n.to_bytes(4, 'little')
    elif ( 0x8000 <= n < 0x800000 ):
        return n.to_bytes(3, 'little')
    elif ( 0x80 <= n < 0x8000 ):
        return n.to_bytes(2, 'little')
    elif ( 0 <= n < 0x80 ):
        return n.to_bytes(1, 'little')
    else:
        raise ScriptError("ScriptNum error") 
    
def sequence_number( n, t ):
    assert t in ('blocks', 'seconds')
    if t == 'blocks':
        # Blocks
        assert ( 0 <= n <= 0xffff )
        return n
    else:
        # Seconds
        assert ( 0 <= n <= (0xffff << 9) )
        return (1 << 22) | (n >> 9)
        
    
# Price

import json
import urllib.request as urll

def get_price():
    priceurl = "https://api.coinmarketcap.com/v2/ticker/1831/?convert=EUR"
    
    pricedata = None
    with urll.urlopen(priceurl, timeout=4) as u:
        pricedata = json.loads(u.read().decode())
        
    return pricedata['data']['quotes']['EUR']['price'] if pricedata else None
                             