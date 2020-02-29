#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import urllib.request as urll

from address import Address

def get_address_utxos( address ):
    ''' address: Address '''
    print("get_address_utxos")
    
    confirmed_outputs_url = "https://api.blockchair.com/bitcoin-cash/outputs"
    unconfirmed_outputs_url = "https://api.blockchair.com/bitcoin-cash/mempool/outputs"
    req = "?q=is_spent(false),recipient({})".format(address.to_cash())
    
    utxos = []
    for outurl in ( confirmed_outputs_url, unconfirmed_outputs_url ):
        addrurl = outurl + req
        
        with urll.urlopen(addrurl, timeout=10) as u:
            addrdata = json.loads(u.read().decode())
           
        for o in addrdata['data']:
            utxos.append( {'txid': o['transaction_hash'], 'index': o['index'], 'value': int(o['value']), 'address': address})
    
    return utxos
    