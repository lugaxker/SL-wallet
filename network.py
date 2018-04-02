#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

from crypto import dsha256

# BTC constants 
DEFAULT_PORT = 8333
START_STRING = 0xd9b4bef9

PROTOCOL_VERSION = 70015
SPV_SERVICES = 0
ZERO_NONCE = 0
NO_RELAY = 0

localhost_ipv6_address = 0x00000000000000000000ffff7f000001 #127.0.0.1

# --- Version message ---

# Protocol Version
version = PROTOCOL_VERSION.to_bytes(4, 'little')

# Services
services = SPV_SERVICES.to_bytes(8, 'little')

# Timestamp
t = int( time.time() )
timestamp = t.to_bytes(8, 'little')

# Receiving address
addr_recv_services = SPV_SERVICES.to_bytes(8, 'little')
addr_recv_ip = localhost_ipv6_address.to_bytes(16,'big')
addr_recv_port = DEFAULT_PORT.to_bytes(2,'big')
addr_recv = addr_recv_services + addr_recv_ip + addr_recv_port

# Transmitting address
addr_trans_services = SPV_SERVICES.to_bytes(8, 'little')
addr_trans_ip = localhost_ipv6_address.to_bytes(16,'big')
addr_trans_port = DEFAULT_PORT.to_bytes(2,'big')
addr_trans = addr_trans_services + addr_trans_ip + addr_trans_port

# Nonce
nonce = ZERO_NONCE.to_bytes(8, 'little')

user_agent_bytes = bytes([0x00])

last_block = 524030 # !!!
start_height = last_block.to_bytes(4, 'little')

relay = bytes([NO_RELAY])

payload = version + services + timestamp + addr_recv + addr_trans + nonce + user_agent_bytes + start_height + relay
payload_len = bytes([len(payload)])
checksum = dsha256( payload )[:4]

magic = START_STRING.to_bytes(4,'little')

msg = "version".encode('ascii')
command = msgb + ( ( 12 - len(msg) ) * b"\00" )

message = magic + command + payload_len + checksum + payload

print("Version message", message.hex())




