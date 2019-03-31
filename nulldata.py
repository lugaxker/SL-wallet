#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from util import (push_data, read_data, op_number, read_op_number)

''' Nulldata (RETURN) output processing. '''

class NullDataError(Exception):
    pass

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
    else:
        raise NullDataError("The nulldata protocol cannot be identified.")


''' Memo protocol. Specifications at https://memo.cash/protocol. '''

# OP_RETURN
OP_RETURN = 0x6a
    
# Action codes
MEMO_SET_PROFILE_NAME = 0x6d01
MEMO_POST = 0x6d02
MEMO_REPLY = 0x6d03
MEMO_LIKE_AND_TIP = 0x6d04
MEMO_SET_PROFILE_TEXT = 0x6d05
MEMO_FOLLOW_USER = 0x6d06
MEMO_UNFOLLOW_USER = 0x6d07
MEMO_SET_PROFILE_PICTURE = 0x6d0a
MEMO_POST_IN_TOPIC = 0x6d0c
MEMO_FOLLOW_TOPIC = 0x6d0d
MEMO_UNFOLLOW_TOPIC = 0x6d0e
MEMO_CREATE_POLL = 0x6d10
MEMO_ADD_POLL_OPTION = 0x6d13
MEMO_VOTE_IN_POLL = 0x6d14
MEMO_SEND_MONEY = 0x6d24

def create_memo_script( prefix, content ):
    ''' prefix (int): action code
        content (list of str) '''
    prefix_bytes = prefix.to_bytes(2, 'big')
    if prefix in (MEMO_SET_PROFILE_NAME, MEMO_POST, MEMO_SET_PROFILE_TEXT, MEMO_SET_PROFILE_PICTURE,
                  MEMO_POST_IN_TOPIC, MEMO_FOLLOW_TOPIC, MEMO_UNFOLLOW_TOPIC):
        return ( bytes( [OP_RETURN] ) + push_data(prefix_bytes) +
                 bytes().join( push_data( d.encode('utf-8') ) for d in content ) )
    elif prefix in (MEMO_REPLY, MEMO_LIKE_AND_TIP, MEMO_ADD_POLL_OPTION, MEMO_VOTE_IN_POLL):
        return ( bytes( [OP_RETURN] ) + push_data( prefix_bytes ) + push_data( bytes.fromhex( content[0] )[::-1] ) +
                 bytes().join( push_data( d.encode('utf-8') ) for d in content[1:] ) )
    elif prefix in (MEMO_FOLLOW_USER, MEMO_UNFOLLOW_USER, MEMO_SEND_MONEY):
        return ( bytes( [OP_RETURN] ) + push_data(prefix_bytes) +
                 push_data( bytes.fromhex( content[0] ) ) +
                 bytes().join( push_data( d.encode('utf-8') ) for d in content[1:] ) )
    elif prefix == MEMO_CREATE_POLL:
        poll_type = op_number( content[0] )
        option_count = op_number( content[1] )
        return ( bytes( [OP_RETURN] ) + push_data( prefix_bytes ) + bytes( [poll_type, option_count] ) + 
                 bytes().join( push_data( d.encode('utf-8') ) for d in content[2:] ) )
    
    else:
        raise NullDataError("cannot serialize memo script")
    
def parse_memo_script( script ):
    return_byte, script = script[0], script[1:]
    assert return_byte == OP_RETURN
    prefix_bytes, script = read_data( script )
    prefix = int.from_bytes(prefix_bytes, 'big')
    content = []
    if prefix in (MEMO_SET_PROFILE_NAME, MEMO_POST, MEMO_SET_PROFILE_TEXT, 
                  MEMO_SET_PROFILE_PICTURE, MEMO_POST_IN_TOPIC, 
                  MEMO_FOLLOW_TOPIC, MEMO_UNFOLLOW_TOPIC):
        while script != bytes():
            b, script = read_data( script )
            content.append( b.decode('utf-8') )
    elif prefix in (MEMO_REPLY, MEMO_LIKE_AND_TIP, MEMO_ADD_POLL_OPTION, MEMO_VOTE_IN_POLL):
        b, script = read_data( script )
        content.append( b[::-1].hex() )
        while script != bytes():
            b, script = read_data( script )
            content.append( b.decode('utf-8') )
    elif prefix in (MEMO_FOLLOW_USER, MEMO_UNFOLLOW_USER):
        b, script = read_data( script )
        content.append( b.hex() )
        while script != bytes():
            b, script = read_data( script )
            content.append( b.decode('utf-8') )
    elif prefix == MEMO_CREATE_POLL:
        poll_type, script = read_op_number(script[0]), script[1:]
        option_count, script = read_op_number(script[0]), script[1:]
        content += [poll_type, option_count]
        while script != bytes():
            b, script = read_data( script )
            content.append( b.decode('utf-8') )
            
    else:
        raise NullDataError("cannot deserialize memo script")
    
    return prefix, content
    
if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
        
    prefix = 0x5d05
    protocol = get_protocol( prefix )
    print(protocol)

    ''' Memo tests. '''
    print()
    print("memo post")
    memo_post = "026d023a4d656d6f206973207468652066697273742064617070207468617420686173206d6f7265207573657273207468616e20696e766573746f72732e"
    script = bytes.fromhex(memo_post)
    
    prefix, content = parse_memo_script( script )
    print("prefix", prefix)
    print("content", content)
    assert create_memo_script( prefix, content ) == script
    
    print()
    print("memo reply")
    memo_reply= "026d0320acf9106666ddfd02732f784631034a3e936ef31478b35966ea7fc2742c5049274c6a486d6d2c20776861742069737375652061726520796f7520686176696e67207769746820746f7020706f7374733f204f722061726520796f7520736179696e6720696e2067656e6572616c2069742773206e6f7420737572666163696e6720676f6f6420706f7374733f"
    script = bytes.fromhex(memo_reply)
    
    prefix, content = parse_memo_script( script )
    print("prefix", prefix)
    print("content", content)
    assert create_memo_script( prefix, content ) == script
    
    print()
    print("memo follow")    
    memo_follow = "026d06145cda42316423273794f74723cc9ba3511d95cb52" 
    script = bytes.fromhex(memo_follow)
    
    prefix, content = parse_memo_script( script )
    print("prefix", prefix)
    print("content", content)
    assert create_memo_script( prefix, content ) == script
    
    print()    
    print("memo create poll")    
    memo_poll = "026d1051524c9d492077616e7420746f2073656520686f77206d616e792070656f706c652063757272656e746c7920757365204d656d6f206f6e20612064617920746f206461792062617369732e2053746174732070616765206f6e6c792073686f777320746f74616c2075736572732e20536f2077697468207468617420696e206d696e642c20686f77206f6674656e20646f20796f75207669736974204d656d6f3f"
    script = bytes.fromhex(memo_poll)
    
    prefix, content = parse_memo_script( script )
    print("prefix", prefix)
    print("content", content)
    assert create_memo_script( prefix, content ) == script
