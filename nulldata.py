#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Nulldata (RETURN) output analysis. '''


# 4-byte prefixes 
#  https://github.com/bitcoincashorg/bitcoincash.org/blob/master/etc/protocols.csv
CASH_ACCOUNT = 0x01010101

def get_protocol( prefix ):
    if 0x6d00 <= prefix <= 0x6dff:
        return "memo"
    elif 0x8d00 <= prefix <= 0x8dff:
        return "blockpress"
    elif 0x9d00 <= prefix <= 0x9dff:
        return "matter"
    elif prefix == CASH_ACCOUNT:
        return "cashaccount"
    
if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
        
    prefix = 0x6d05
    protocol = get_protocol( prefix )
    print(protocol)

