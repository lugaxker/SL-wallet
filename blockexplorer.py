#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import urllib.request as urll

from address import Address

def get_address_utxos( address ):
    ''' address: Address '''
    print("get_address_utxos")
    addr = address.to_cash()
    
    confirmed_outputs_url = "https://api.blockchair.com/bitcoin-cash/outputs"
    unconfirmed_outputs_url = "https://api.blockchair.com/bitcoin-cash/mempool/outputs"
    req = "?q=is_spent(0),recipient({})".format(addr)
    
    utxos = []
    for outurl in (confirmed_outputs_url, unconfirmed_outputs_url):
        addrurl = outurl + req
        
        with urll.urlopen(addrurl, timeout=4) as u:
            addrdata = json.loads(u.read().decode())
            
        for o in addrdata['data']:
            utxos.append( {'txid': o['transaction_hash'], 'index': o['index'], 'value': int(o['value']), 'address': address})
    
    return utxos
    
if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    addr = Address.from_string( "qq7ur36zd8uq2wqv0mle2khzwt79ue9ty57mvd95r0" )
    utxos = get_address_utxos( addr )
    for o in utxos:
        print(o)
    value = sum( o['value'] for o in utxos )
    print( "value: {:.8f} BCH".format( value/1e8 ) )
    