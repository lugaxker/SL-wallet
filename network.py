#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import random
import socket

from crypto import dsha256

# BTC constants 
DEFAULT_PORT = 8333
START_STRING = 0xd9b4bef9

PROTOCOL_VERSION = 70015
SPV_SERVICES = 0
RELAY = False

localhost_ipv6_address = 0x00000000000000000000ffff7f000001 #127.0.0.1

def make_message( cmd, payload ):
    ''' Message Structure for Bitcoin Protocol.
    cmd (str) : command (e.g. "version")
    payload (bytes) : actual data '''
    
    magic = START_STRING.to_bytes(4,'little')
    cmdb = cmd.encode('ascii')
    command = cmdb + ( ( 12 - len(cmdb) ) * b"\00" )
    length = len(payload).to_bytes(4, 'little')
    checksum = dsha256( payload )[:4]
    return magic + command + length + checksum + payload

def version_message(last_block):
    ''' Version message. '''
    
    # Protocol Version
    version = PROTOCOL_VERSION.to_bytes(4, 'little')

    # Services
    services = SPV_SERVICES.to_bytes(8, 'little')
    
    # Timestamp
    t = int( time.time() )
    timestamp = t.to_bytes(8, 'little')
    
    # Receiving address
    addr_recv  = SPV_SERVICES.to_bytes(8, 'little')
    addr_recv += localhost_ipv6_address.to_bytes(16,'big')
    addr_recv += DEFAULT_PORT.to_bytes(2,'big')
    
    # Transmitting address
    addr_trans  = SPV_SERVICES.to_bytes(8, 'little')
    addr_trans += localhost_ipv6_address.to_bytes(16,'big')
    addr_trans += DEFAULT_PORT.to_bytes(2,'big')
    
    # Nonce
    nonce = random.getrandbits(64).to_bytes(8, 'little')
    
    user_agent_bytes = bytes([0x00])
    start_height = last_block.to_bytes(4, 'little')
    relay = bytes([RELAY])
    
    payload = version + services + timestamp + addr_recv + addr_trans + nonce + user_agent_bytes + start_height + relay
    
    return payload
    

if __name__ == '__main__':
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    host = "195.154.227.47"
    port = DEFAULT_PORT
    print("connecting to node...")
    sock.connect((host,port))
    
    last_block = 516269 # !!!
    payload = version_message(last_block)
    message = make_message("version", payload)
    print("Version message", message.hex())
    sock.send( message )
    
    m = sock.recv( 1024 )
    print("version", m.hex())
    
    m = sock.recv( 1024 )
    print("verack", m.hex())

    sock.close()
    


