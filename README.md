SL-wallet
=========

Project of a multicurrency lightweight wallet.

## Prerequisites

Python 3.5 or higher. Packages : `ecdsa`, `hashlib`, `hmac`, `pbkdf2`, `socket`, `threading`, `collections` (deque).

## Tasks

### Done

Create and broadcast a transaction on the network. `broadcast_transaction.py`

Create and use of a multisig address. `multisig.py`

Extended keys and child key derivation. `crypto.py`

Estimate size of transaction in order to compute transaction fees. Multiple input and output transactions. `transaction.py`

### In progress

Handle a peer connexion in order to get wallet information. `network.py`

Store keys and other information (addresses, transactions). `wallet.py`

Some SegWit stuff (BTC). `segwit.py`


### To do

Manage blockchain headers. `blockchain.py` (yet to create) 

## Coin support

Bitcoin Cash (BCH)