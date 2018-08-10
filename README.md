SL-wallet
=========

Project of a multicurrency lightweight wallet.

## Prerequisites

Python 3.5 or higher. Packages : `ecdsa`, `hashlib`, `hmac`, `pbkdf2`, `socket`, `threading`, `collections` (deque), `json`.

## Quick overview

`base58.py`  Base58Check conversion.

`crypto.py`  Cryptography classes and functions: hash functions, ECDSA (private keys, public keys), extended keys, child key derivation, accounts.

`mnemonic.py` Mnemonic phrases.

`address.py`  Address class: legacy and cash format, kinds (P2PKH, P2SH).

`script.py`  Scripting: locking scripts and unlocking scripts for P2PK, P2PKH, P2SH.

`transaction.py`  Building of transactions.

`network.py`  Network peer connexions.

`wallet.py`

## Tasks

### Done

Create and broadcast a transaction on the network. `broadcast_transaction.py`

Create and use of a multisig address. `multisig.py`

Extended keys and child key derivation. `crypto.py`

Estimate size of transaction in order to compute transaction fees. Multiple input and output transactions. `transaction.py`

### In progress

Handle a peer connexion in order to get wallet information. `network.py`

Store keys and other information (addresses, transactions). `wallet.py`

Manage blockchain headers. `blockchain.py`

Some SegWit stuff (BTC). `segwit.py`



## Coin support

Bitcoin Cash (BCH)