#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class Inventory:
    MSG_ERROR = 0
    MSG_TX    = 1
    MSG_BLOCK = 2
    MSG_FILTERED_BLOCK = 3
    MSG_CMPCT_BLOCK = 4
    
    def __init__(self, t=MSG_ERROR, h=None):
        self.t = t
        self.h = h
        
    def __eq__(self, other):
        return ( self.t == other.t ) & ( self.h == other.h )

    def __ne__(self, other):
        return ( self.t != other.t ) | ( self.h != other.h )
    
    @classmethod
    def from_tx_id(self, txid ):
        if isinstance( txid, str ):
            txid = bytes.fromhex( txid )
        return self( self.MSG_TX, txid[::-1] )
    
    @classmethod
    def from_block_id(self, blockid ):
        if isinstance( blockid, str ):
            blockid = bytes.fromhex( blockid )
        return self( self.MSG_BLOCK, blockid[::-1] )
    
    @classmethod
    def deserialize(self, inv):
        assert len(inv) == 36
        t = int.from_bytes(inv[:4], 'little')
        h = inv[4:]
        return self(t, h)
    
    def serialize(self):
        if self.t == self.MSG_ERROR:
            raise Exception("wrong inventory type")
        return self.t.to_bytes(4, 'little') + self.h
    
    def __str__(self):
        return self.__repr__()
    
    def __repr__(self):
        return "<Inventory {} {}>".format(
                { self.MSG_ERROR: "error",
                  self.MSG_TX   : "tx",
                  self.MSG_BLOCK: "block" }[self.t], 
                self.h[::-1].hex() )
                
if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
        
    txid = "78adb517860e972c494273fbde9d9aaeb053a74355acf196a8160f1dae1f229b"
    inv1 = Inventory.from_tx_id( txid )
    print(inv1)
    print(inv1.serialize().hex())
    
    blockid = "0000000000000000009802f7fbfb6cd5cd97828987c0a1de132df8979ac3ba30"
    inv2 = Inventory.from_block_id( blockid )
    print(inv2)
    print(inv2.serialize().hex())
    

        