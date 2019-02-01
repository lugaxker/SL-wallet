#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import unicodedata

import math
import ecdsa

from crypto import sha256, getrandrange

def load_wordlist(filename):
    path = os.path.join(os.path.dirname(__file__), 'wordlists', filename)
    with open(path, 'r') as f:
        s = f.read().strip()
    s = unicodedata.normalize('NFKD', s)
    lines = s.split('\n')
    wordlist = []
    for line in lines:
        line = line.split('#')[0]
        line = line.strip(' \r')
        assert ' ' not in line
        if line:
            wordlist.append(line)
    return wordlist

def mnemonic_checksum(entropy, nbits=128):
    return ( int.from_bytes( sha256( entropy.to_bytes(nbits//8,'big') ), 'big' )
            >> (256 - nbits//32) )

def encode_mnemonic(entropy, wordlist, nbits=128 ):
    ''' Encodes BIP-39 mnemonic phrase from entropy.
    entropy (int): random number 
    wordlist (str list): list of words from BIP-39 spec
    nbits (int): number of bits of entropy '''
    bpw = math.ceil( math.log(len(wordlist), 2) )
    nwords = (nbits + nbits//32) // bpw
    y = (entropy << nbits//32) + mnemonic_checksum(entropy, nbits)
    words = []
    for i in range(nwords-1, -1, -1):
        j = bpw * i
        x = y >> j
        y -= x << j
        words += [ wordlist[x] ]
    return " ".join(words)

def decode_mnemonic(mnemonic, wordlist):
    '''Decodes BIP-39 mnemonic phrase.
    mnemonic (str): mnemonic phrase (can contain 12, 15, 18, 21 or 24 words)
    wordlist (str list): list of words from BIP-39 spec'''
    bpw = math.ceil( math.log(len(wordlist), 2) )
    words = mnemonic.split()
    nwords = len(words)
    y = 0
    for i in range(nwords):
        w = words.pop()
        k = wordlist.index(w)
        y += k << i*bpw
    checkbits = ((nwords*bpw) // 32)
    checksum = y % (1 << checkbits)
    entropy = (y - checksum) >> checkbits
    assert checksum == mnemonic_checksum(entropy, checkbits*32), "Invalid mnemonic: wrong checksum"
    return entropy

def generate_mnemonic( nbits=128, filename = "english.txt" ):
    '''Generates a random BIP-39 mnemonic phrase.'''
    if nbits not in [128,160,192,224,256]:
        raise ValueError("Number of random bits must be 128, 160, 192, 224 or 256")
    wordlist = load_wordlist(filename)
    entropy = getrandrange(1 << nbits)    
    return encode_mnemonic(entropy, wordlist, nbits)
