#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from base58 import *
from crypto import (hash160, PublicKey)

from constants import *

class AddressError(Exception):
    '''Exception used for Address errors.'''

class CashAddr:
    # Copyright (C) 2017 The Electron Cash Developers
    
    _CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    @staticmethod
    def _polymod(values):
        """Internal function that computes the cashaddr checksum."""
        c = 1
        for d in values:
            c0 = c >> 35
            c = ((c & 0x07ffffffff) << 5) ^ d
            if (c0 & 0x01):
                c ^= 0x98f2bc8e61
            if (c0 & 0x02):
                c ^= 0x79b76d99e2
            if (c0 & 0x04):
                c ^= 0xf33e5fb3c4
            if (c0 & 0x08):
                c ^= 0xae2eabe2a8
            if (c0 & 0x10):
                c ^= 0x1e4f43e470
        retval= c ^ 1
        return retval
    
    @staticmethod
    def _prefix_expand(prefix):
        """Expand the prefix into values for checksum computation."""
        retval = bytearray(ord(x) & 0x1f for x in prefix)
        # Append null separator
        retval.append(0)
        return retval
    
    @staticmethod
    def _create_checksum(prefix, data):
        """Compute the checksum values given prefix and data."""
        values = CashAddr._prefix_expand(prefix) + data + bytes(8)
        polymod = CashAddr._polymod(values)
        # Return the polymod expanded into eight 5-bit elements
        return bytes((polymod >> 5 * (7 - i)) & 31 for i in range(8))

    @staticmethod
    def _convertbits(data, frombits, tobits, pad=True):
        """General power-of-2 base conversion."""
        acc = 0
        bits = 0
        ret = bytearray()
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        for value in data:
            acc = ((acc << frombits) | value ) & max_acc
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)

        if pad and bits:
            ret.append((acc << (tobits - bits)) & maxv)

        return ret

    @staticmethod
    def _pack_addr_data(kind, addr_hash):
        """Pack addr data with version byte"""
        version_byte = kind << 3

        offset = 1
        encoded_size = 0
        if len(addr_hash) >= 40:
            offset = 2
            encoded_size |= 0x04
        encoded_size |= (len(addr_hash) - 20 * offset) // (4 * offset)

        # invalid size?
        if ((len(addr_hash) - 20 * offset) % (4 * offset) != 0
                or not 0 <= encoded_size <= 7):
            raise ValueError('invalid address hash size {}'.format(addr_hash))

        version_byte |= encoded_size

        data = bytes([version_byte]) + addr_hash
        return CashAddr._convertbits(data, 8, 5, True)

    @staticmethod
    def _decode_payload(addr):
        """Validate a cashaddr string.

        Throws CashAddr.Error if it is invalid, otherwise returns the
        triple

        (prefix,  payload)

        without the checksum.
        """
        lower = addr.lower()
        if lower != addr and addr.upper() != addr:
            raise ValueError('mixed case in address: {}'.format(addr))

        parts = lower.split(':', 1)
        if len(parts) != 2:
            raise ValueError("address missing ':' separator: {}".format(addr))

        prefix, payload = parts
        if not prefix:
            raise ValueError('address prefix is missing: {}'.format(addr))
        if not all(33 <= ord(x) <= 126 for x in prefix):
            raise ValueError('invalid address prefix: {}'.format(prefix))
        if not (8 <= len(payload) <= 124):
            raise ValueError('address payload has invalid length: {}'
                            .format(len(addr)))
        try:
            data = bytes(CashAddr._CHARSET.find(x) for x in payload)
        except ValueError:
            raise ValueError('invalid characters in address: {}'
                                .format(payload))

        if CashAddr._polymod(CashAddr._prefix_expand(prefix) + data):
            raise ValueError('invalid checksum in address: {}'.format(addr))

        if lower != addr:
            prefix = prefix.upper()

        # Drop the 40 bit checksum
        return prefix, data[:-8]

    #
    # External Interface
    #

    PUBKEY_TYPE = 0
    SCRIPT_TYPE = 1

    @staticmethod
    def decode(address):
        '''Given a cashaddr address, return a triple

            (prefix, kind, hash)
        '''
        if not isinstance(address, str):
            raise TypeError('address must be a string')

        prefix, payload = CashAddr._decode_payload(address)

        # Ensure there isn't extra padding
        extrabits = len(payload) * 5 % 8
        if extrabits >= 5:
            raise ValueError('excess padding in address {}'.format(address))

        # Ensure extrabits are zeros
        if payload[-1] & ((1 << extrabits) - 1):
            raise ValueError('non-zero padding in address {}'.format(address))

        decoded = CashAddr._convertbits(payload, 5, 8, False)
        version = decoded[0]
        addr_hash = bytes(decoded[1:])
        size = (version & 0x03) * 4 + 20
        # Double the size, if the 3rd bit is on.
        if version & 0x04:
            size <<= 1
        if size != len(addr_hash):
            raise ValueError('address hash has length {} but expected {}'
                            .format(len(addr_hash), size))

        kind = version >> 3
        if kind not in (CashAddr.SCRIPT_TYPE, CashAddr.PUBKEY_TYPE):
            raise ValueError('unrecognised address type {}'.format(kind))

        return prefix, kind, addr_hash

    @staticmethod
    def encode(prefix, kind, addr_hash):
        """Encode a cashaddr address without prefix and separator."""
        if not isinstance(prefix, str):
            raise TypeError('prefix must be a string')

        if not isinstance(addr_hash, (bytes, bytearray)):
            raise TypeError('addr_hash must be binary bytes')

        if kind not in (CashAddr.SCRIPT_TYPE, CashAddr.PUBKEY_TYPE):
            raise ValueError('unrecognised address type {}'.format(kind))

        payload = CashAddr._pack_addr_data(kind, addr_hash)
        checksum = CashAddr._create_checksum(prefix, payload)
        return ''.join([CashAddr._CHARSET[d] for d in (payload + checksum)])

    @staticmethod
    def encode_full(prefix, kind, addr_hash):
        """Encode a full cashaddr address, with prefix and separator."""
        return ':'.join([prefix, CashAddr.encode(prefix, kind, addr_hash)])

class Address:
    ''' Address. 
    .kind: address kind (P2PKH or P2SH)
    .h: 20-byte information (hash of public key or redeem script)'''
    
    def __init__(self, h, kind):
        assert kind in (Constants.CASH_P2PKH, Constants.CASH_P2SH)
        self.kind = kind
        assert len(h) == 20
        self.h = h
        
    def __eq__(self, other):
        return ( self.kind == other.kind ) & ( self.h == other.h )

    def __ne__(self, other):
        return ( self.kind != other.kind ) | ( self.h != other.h )

    @classmethod
    def from_cash_string(self, string):
        '''Initialize from a cash address string.'''
        prefix = Constants.CASH_HRP
        #if string.upper() == string:
            #prefix = prefix.upper()
        if not string.startswith(prefix + ':'):
            string = ':'.join([prefix, string])
        addr_prefix, kind, addr_hash = CashAddr.decode(string)
        if addr_prefix != prefix:
            raise AddressError('address has unexpected prefix {}'
                               .format(addr_prefix))
        return self(addr_hash, kind)
    
    @classmethod
    def from_legacy_string(self, string):
        '''Initialize from a legacy address string.'''
        vpayload = Base58.decode_check( string )
        verbyte, addr_hash = vpayload[0], vpayload[1:]
        if verbyte == Constants.LEGACY_P2PKH:
            kind = Constants.CASH_P2PKH
        elif verbyte == Constants.LEGACY_P2SH:
            kind = Constants.CASH_P2SH
        else:
            raise AddressError("unknown version byte: {}".format(verbyte))
        return self(addr_hash, kind)
    
    @classmethod
    def from_string(self, string):
        '''Construct from an address string.'''
        if len(string) > 35:
            return self.from_cash_string(string)
        else:
            return self.from_legacy_string(string)
    
    @classmethod
    def from_pubkey_hash(self, pubkey_hash):
        '''Initializes from a public key hash.'''
        return self(pubkey_hash, Constants.CASH_P2PKH)
    
    @classmethod
    def from_pubkey(self, pubkey):
        '''Returns a P2PKH address from a public key. The public
        key can be serialized as a bytes or a hex string.'''
        if isinstance(pubkey, PublicKey):
            return self.from_pubkey_hash( hash160( pubkey.to_ser() ) )
        elif isinstance(pubkey, bytes): 
            return self.from_pubkey_hash( hash160( pubkey ) )
        elif isinstance(pubkey, hex):
            return self.from_pubkey_hash( hash160( bytes.fromhex(pubkey) ) )
        else:
            raise AddressError("wrong type of public key")

    @classmethod
    def from_script_hash(self, script_hash):
        '''Initializes from a redeem script hash.'''
        return self(script_hash, Constants.CASH_P2SH)
    
    @classmethod
    def from_script(self, script):
        '''Initializes from a redeem script.'''
        return self.from_script_hash(hash160(script))

    def to_cash(self):
        return CashAddr.encode(Constants.CASH_HRP, self.kind, self.h)
    
    def to_full_cash(self):
        return CashAddr.encode_full(Constants.CASH_HRP, self.kind, self.h)
    
    def to_legacy(self):
        if self.kind == Constants.CASH_P2PKH:
            verbyte = Constants.LEGACY_P2PKH
        else:
            verbyte = Constants.LEGACY_P2SH
        return Base58.encode_check(bytes([verbyte]) + self.h)
    
    def to_string(self):
        return self.to_cash()
        
    def __str__(self):
        return self.to_full_cash()

    def __repr__(self):
        return '<Address {}>'.format(self.to_cash())