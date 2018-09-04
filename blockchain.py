#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import dsha256

from constants import *

BLOCK_VERSION = 1 << 5

class BlockchainError(Exception):
    '''Exception used for Blockchain errors.'''

class BlockHeader:
    
    def __init__(self, version=BLOCK_VERSION, prev_block_id=bytes(32), 
                 merkle_root=bytes(32), timestamp=0, bits=0, nonce=0):
        self.version = version
        self.prev_block_id = prev_block_id
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        
    @classmethod
    def from_serialized(self, raw):
        version = int.from_bytes( raw[:4], 'little' )
        prev_block_id = raw[4:36][::-1]
        merkle_root = raw[36:68][::-1]
        timestamp = int.from_bytes( raw[68:72], 'little')
        bits = int.from_bytes( raw[72:76], 'little')
        nonce = int.from_bytes( raw[76:80], 'little')
        return self(version, prev_block_id, merkle_root, timestamp, bits, nonce)
    
    @classmethod
    def genesis(self):
        version = Constants.GENESIS_BLOCK_VERSION
        prev_block_id = bytes(32)
        merkle_root = bytes.fromhex( Constants.GENESIS_MERKLE_ROOT )
        timestamp = Constants.GENESIS_BLOCK_TIMESTAMP
        bits = Constants.GENESIS_BLOCK_BITS
        nonce = Constants.GENESIS_BLOCK_NONCE
        return self(version, prev_block_id, merkle_root, timestamp, bits, nonce)
        
    def serialize(self):
        nVersion = self.version.to_bytes(4, 'little')
        nTime = self.timestamp.to_bytes(4, 'little')
        nBits = self.bits.to_bytes(4, 'little')
        nNonce = self.nonce.to_bytes(4, 'little')
        
        return (nVersion + self.prev_block_id[::-1] + self.merkle_root[::-1] + 
                nTime + nBits + nNonce)
    
    def block_id(self):
        raw = self.serialize()
        return dsha256( raw )[::-1]
    
    def target(self):
        mant = self.bits & 0x007fffff
        r = ( self.bits >> 24 ) & 0xff
        neg = -1 if ( self.bits & 0x00800000 ) != 0 else 1
        if r <= 3:
            return neg * (mant >> (8 * (3 - r)))
        else:
            return neg * (mant << (8 * (r - 3)))
        
    def difficulty(self):
        return self.target() / 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    
    def check(self):
        return int.from_bytes( dsha256( self.serialize() ), 'little') <= self.target()
    
    def __str__(self):
        return self.__repr__()
    
    def __repr__(self):
        return "<BlockHeader {}>".format(self.block_id().hex())
    
    
def check_headerchain_file( filename ):
    with open(filename, "rb") as f:
        height = 0
        raw_hdr =  f.read(Constants.BLOCKHEADER_SIZE)
        header = BlockHeader.from_serialized( raw_hdr )
        while raw_hdr != bytes():
            if not header.check():
                raise BlockchainError("Headerchain not valid at block height {:d}:\n {}".format(height, raw_hdr.hex()))
            height += 1
            raw_hdr = f.read(Constants.BLOCKHEADER_SIZE)
            header = BlockHeader.from_serialized( raw_hdr )
            
    return height

class Blockchain:
    
    def __init__(self, headers):
        self.headers = headers
        self.height = len(self.headers) - 1
    
    @classmethod
    def load(self, filename="headerchain"):
        try:
            f = open(filename, "rb")
        except:
            # File cannot be opened: we have to construct the genesis header
            genesis_block_header = BlockHeader.genesis()
            assert (genesis_block_header.block_id().hex() 
                    == Constants.GENESIS_BLOCK_ID)
            return self( [ genesis_block_header.serialize() ] )
        else:
            # File is opened
            headers = []
            hdr = f.read(Constants.BLOCKHEADER_SIZE)
            while hdr != bytes():
                headers.append( hdr )
                hdr = f.read(Constants.BLOCKHEADER_SIZE)
            return self( headers )
        
    def save(self, filename="headerchain"):
        with open(filename, "wb") as f:
            for hdr in self.headers:
                f.write(hdr)
                
    def check(self):
        prev_header = BlockHeader.genesis()
        for hdr in self.headers[1:]:
            header = BlockHeader.from_serialized( hdr )
            if (not header.check()) | (prev_header.block_id() != header.prev_block_id):
                return False
            else:
                prev_header = header
        return True
            
            
    def get_header(self, i):
        if len(self.headers) < i:
            return None
        return BlockHeader.from_serialized( self.headers[i] )
    
    def get_height(self):
        return self.height
    
    def add_headers(self, block_headers):
        last_header = BlockHeader.from_serialized( self.headers[-1] )
        for hdr in block_headers:
            header = BlockHeader.from_serialized(hdr)
            if not header.check():
                raise BlockchainError("invalid header: {}".format(header) )
            if last_header.block_id() != header.prev_block_id:
                raise BlockchainError("cannot link {} to the chain".format(header))
            self.headers.append( hdr )
            self.height += 1
            last_header = header
    
    def get_block_locators(self):
        # Used in getheaders network message.
        step = 1
        index = self.height
        block_locators = []
        while index > 0:
            if len(block_locators) >= 10:
                step *= 2
            header = BlockHeader.from_serialized( self.headers[index] )
            block_locators.append( header.block_id() )
            index -= step
        
        # Genesis block
        genesis_header = BlockHeader.genesis()
        block_locators.append( genesis_header.block_id() )
        return block_locators
    
    def __str__(self):
        return self.__repr__()
    
    def __repr__(self):
        return "<Blockchain object: height={:d}>".format(self.height)
        


if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    # Block 1
    raw_hdr = bytes.fromhex("010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299")
    hdr = BlockHeader.from_serialized( raw_hdr )
    
    block_id = hdr.block_id()
    print(block_id.hex())
    
    target = hdr.target()
    print(target)
    
    diff = hdr.difficulty()
    print(diff)
    
    print("check:", hdr.check() )
    print()
    
    # Header chain
    blc = Blockchain.load()
    is_valid = blc.check()
    print("is headerchain valid?", is_valid)
    
    print()
    print("First block headers")
    n = min( blc.get_height(), 10)
    for i in range(n):
        header = BlockHeader.from_serialized( blc.headers[i] )
        print(i, header.serialize().hex(), header.block_id().hex())
    
    #print("saving")
    #blc.save()
            
    