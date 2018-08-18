#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import dsha256

BLOCK_VERSION = 1 << 5
BLOCKHEADER_SIZE = 80 # 80 bytes

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
    
def read_blockchain_headers_file( filename ):
    with open(filename, "rb") as f:
        height = 0
        raw_hdr =  f.read(BLOCKHEADER_SIZE)
        header = BlockHeader.from_serialized( raw_hdr )
        while raw_hdr != bytes():
            if not header.check():
                raise BlockchainError("Headerchain not valid at block height {:d}:\n {}".format(height, raw_hdr.hex()))
            height += 1
            raw_hdr = f.read(BLOCKHEADER_SIZE)
            header = BlockHeader.from_serialized( raw_hdr )
            
    return height

    


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
    print("10 first block headers")
    filename = "/home/lars/.electron-cash/blockchain_headers"
    with open(filename, "rb") as f:
        i = 0
        header = f.read(80)
        print(i, header.hex())
        while (header != bytes()) & (i < 10):
            i+=1
            header = f.read(80)
            print(i, header.hex())
            
    block_height = read_blockchain_headers_file( filename )
    print( block_height )
        
            
    