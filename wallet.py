#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class Wallet():
    
    def __init__(self):
        self.addresses = {"external": [], "internal": []}
        self.history = {}
        self.keystores = []
        self.transactions = {}
        
        # No encryption for the moment
        self.encrypted = False
        