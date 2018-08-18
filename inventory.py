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
    def from_tx_id(self, tx_id ):
        return self( self.MSG_TX, tx_id[::-1] )
    
    @classmethod
    def from_block_id(self, block_id ):
        return self( self.MSG_BLOCK, block_id[::-1] )
    
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
    

        