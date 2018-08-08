#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
            return b[l::-1].hex(), b[l:]
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