SL-wallet
=========

Project of a multicurrency lightweight wallet.

## Prerequisites

Python 3.5 or higher. Packages : `ecdsa`, `hashlib`, `hmac`, `pbkdf2`, `socket`.

## Tasks

### Done

Create and broadcast a transaction on Bitcoin Cash network. `broadcast_transaction.py`

Create and use of a multisig address. `multisig.py`

Extended keys and child key derivation. `crypto.py`

Estimate size of transaction in order to compute transaction fees. `transaction.py`

### In progress

Some SegWit stuff (BTC). `segwit.py`


### To do

Store keys and other information (addresses, transactions). `wallet.py` (yet to create)

Manage blockchain headers. `blockchain.py` (yet to create) 

## Coin support

Bitcoin Cash (BCH), Bitcoin (BTC), Ethereum (ETH), Dash (DSH)