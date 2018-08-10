#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

import collections
import json
import socket
import threading

from util import (read_bytes, read_var_int)

from crypto import dsha256, getrandrange
from constants import *

SPV_SERVICES = 0
RELAY = False

DEFAULT_IPV6_ADDRESS = 0xffff7f000001 #127.0.0.1

class NetworkError(Exception):
    '''Exception used for Network errors.'''

def serialize_network_address(ip_addr, services, with_timestamp=True):
    ''' Serializes an address transitted on the network. 
    ip_addr (str): IPv4 address (e.g. "127.0.0.1")
    services (int)
    with_timestamp (bool): no timestamp in version message '''
    quads = ip_addr.split(".")
    address = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, int(quads[0]), int(quads[1]), int(quads[2]), int(quads[3])])
    port = Constants.DEFAULT_PORT.to_bytes(2,'big')
    serv = services.to_bytes(8, 'little')
    if with_timestamp:
        timestamp = int( time.time() ).to_bytes(4, 'little')
        return timestamp + serv + address + port
    else:
        return serv + address + port

def deserialize_network_address( data, with_timestamp=True ):
    if with_timestamp and len(data) != 30:
        raise NetworkError('Network address should be 30-byte long') 
    elif not with_timestamp and len(data) != 26:
        raise NetworkError('Network address should be 26-byte long')
    
    if with_timestamp:
        timestamp, data = read_bytes(data, 4, int, 'little')
    
    services, data = read_bytes(data, 8, int, 'little')
    address, data = read_bytes(data, 16, bytes, 'big')
    if address[0:-4] == bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]):
        # IPv4
        host = ".".join("{}".format(v) for v in address[-4:])
    else:
        # IPv6
        host = ""
    port, data = read_bytes(data, 2, int, 'big')
    if with_timestamp:
        return ( (host, port), services, timestamp )
    else:
        return ( (host, port), services )
 
def wrap_network_message( cmd, payload ):
    ''' Message Structure for Bitcoin Protocol.
    cmd (str) : command (e.g. "version")
    payload (bytes) : actual data '''
    magic = Constants.NETWORK_MAGIC.to_bytes(4,'little')
    cmdb = cmd.encode('ascii')
    command = cmdb + ( ( 12 - len(cmdb) ) * b"\00" )
    length = len(payload).to_bytes(4, 'little')
    checksum = dsha256( payload )[:4]
    return magic + command + length + checksum + payload

def unwrap_network_message( data ):
    if len(data) < 24:
        return None, None, None, data
    
    magic = int.from_bytes( data[:4], 'little')
    assert magic == Constants.NETWORK_MAGIC
    
    i = 0
    while data[4+i] != 0 and i < 12:
        i += 1
    try: 
        command = data[4:4+i].decode('ascii')
    except UnicodeDecodeError:
        raise NetworkError("Invalid command encoding")
    
    length = int.from_bytes( data[16:20], 'little' )
    if (len(data) - 24) < length:
        return command, None, length, data
    
    checksum = data[20:24]
    payload = data[24:24+length]
    leftover = data[24+length:]
    assert checksum == dsha256( payload )[:4]
    
    return command, payload, length, leftover


class Network(threading.Thread):
    ''' Network single-peer manager. '''
    
    SERVICES = 0
    TX_RELAY = False
    MAX_MESSAGE_SIZE = 1 << 20 # 1 MiB
    
    def __init__(self, block_height, user_agent="slwallet"):
        threading.Thread.__init__(self)
        self.user_agent = "/{}/".format(user_agent).replace(" ", ":")
        self.load_peer_list()
        self.peer_address = self.peer_list[0]
        assert self.peer_address[1] == Constants.DEFAULT_PORT
        self.block_height = block_height
        self.socket = None
        
    def load_peer_list(self, filename="peers.json"):
        with open(filename, 'r') as f:
            peer_list = json.load(f)
        self.peer_list = [tuple(peer) for peer in peer_list]
        
    def save_peer_list(self, filename="peers.json"):
        with open(filename, 'w') as f:
            json.dump(self.peer_list, f, ensure_ascii=False)

    def start(self):
        self.running = False
        threading.Thread.start(self)
        while not self.running:
            pass
        
    def shutdown(self):
        self.running = False
        self.save_peer_list()
    
    def run(self):
        self.state = 'init'
        self.running = True
        while self.running:
            try:
                self.step()
            except:
                break
            time.sleep(0.1)
    
    def step(self):
        if self.state == 'init':
            self.data_buffer = bytes()
            self.outgoing_data_queue = collections.deque()
            
            self.sent_version = False
            self.peer_verack = 0
            self.handshake = False
            
            if self.socket == None:
                if self.make_connexion():
                    self.state = 'connected'
                    self.send_version()
                    
        elif self.state == 'connected':
            self.handle_outgoing_data()
            self.handle_incoming_data()
        elif self.state == 'dead':
            print("dead")
            self.close_connexion()
            self.running = False
    
    def make_connexion(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        try:
            self.socket.connect(self.peer_address)
            self.socket.settimeout(0.1)
            return True
        except:
            self.state = 'dead'
            return False
        
    def close_connexion(self):
        if self.socket is not None:
            self.socket.close()
            self.socket = None
            
    def handle_incoming_data(self):
        try:
            data = self.socket.recv(4096)
        except ConnectionResetError:
            data = bytes()
        except socket.timeout:
            # No new data
            return
        
        print("incoming data", data.hex() )
        
        if len(data) == 0: # lost connexion
            self.state = 'dead'
            return
        
        self.data_buffer += data
        while self.state != 'dead':
            command, payload, length, self.data_buffer = unwrap_network_message( self.data_buffer )
            
            if length != None and length > self.MAX_MESSAGE_SIZE:
                self.state = 'dead'
                break
            
            if payload == None:
                break
            
            self.handle_command(command, payload)

    def handle_outgoing_data(self):
        while len(self.outgoing_data_queue) > 0:
            q = self.outgoing_data_queue.popleft()
            try:
                r = self.socket.send(q)
                if r < len(q):
                    self.outgoing_data_queue.appendleft(q[r:])
                    return
            except (ConnectionAbortedError, OSError):
                self.state = 'dead'
                break
            
    def handle_command(self, command, payload):
        print("handle command: {}".format(command))
        if self.peer_verack < 2 and command not in ('version', 'verack'):
            raise NetworkError("invalid command")
        try:
            cmd = getattr(self, 'recv_' + command)
        except AttributeError:
            return
        cmd(payload)
        
    def send_version(self):
        print("send verack")
        version = Constants.PROTOCOL_VERSION.to_bytes(4, 'little')
        services = self.SERVICES.to_bytes(8, 'little')
        timestamp = int( time.time() ).to_bytes(8, 'little')
        addr_recv = serialize_network_address(self.peer_address[0], 1, with_timestamp=False)
        addr_trans = serialize_network_address("127.0.0.1", 0, with_timestamp=False)
        nonce = getrandrange( 1 << 64 ).to_bytes(8, 'little')
        user_agent = self.user_agent.encode('ascii')
        user_agent_bytes = bytes([len(user_agent)])
        start_height = self.block_height.to_bytes(4, 'little')
        relay = bytes([self.TX_RELAY])
        payload = (version + services + timestamp + addr_recv + addr_trans + 
                   nonce + user_agent_bytes + user_agent + start_height + relay)
        self.outgoing_data_queue.append( wrap_network_message("version", payload) )
        self.sent_version = True
        
    def recv_version(self, payload):
        if len(payload) < 20:
            self.state = 'dead'
            return
        
        try:
            self.peer_version, payload = read_bytes(payload, 4, int, 'little')
            self.peer_services, payload = read_bytes(payload, 8, int, 'little')
            self.peer_time, payload = read_bytes(payload, 8, int, 'little')
            my_network_address, payload = read_bytes(payload, 26, bytes, 'big')
            my_address, my_services  = deserialize_network_address(my_network_address, with_timestamp=False)
            peer_network_address, payload = read_bytes(payload, 26, bytes, 'big')
            peer_address, peer_services  = deserialize_network_address(peer_network_address, with_timestamp=False)
            nonce, payload = read_bytes(payload, 8, int, 'little')
            peer_user_agent_size, payload = read_var_int(payload)
            peer_user_agent, payload = read_bytes(payload, peer_user_agent_size, hex, 'big')
            self.peer_block_height, payload = read_bytes(payload, 4, int, 'little')
            relay, payload = read_bytes(payload, 1, int, 'little')
            assert payload == bytes()
        except:
            self.state = 'dead'
            return
        
        if self.peer_block_height > self.block_height:
            self.block_height = self.peer_block_height
        
        self.send_verack()
        self.peer_verack += 1

        if not self.sent_version:
            self.send_version()
        
        if self.peer_verack == 2:
            self.handshake = True
            print("handshake done")
        
    def send_verack(self):
        self.outgoing_data_queue.append( wrap_network_message("verack", bytes()) )
    
    def recv_verack(self, payload):
        assert payload == bytes()
        self.peer_verack += 1
        if self.peer_verack == 2:
            self.handshake = True
            print("handshake done")
            
    def send_pong(self, payload):
        self.outgoing_data_queue.append( wrap_network_message("pong", payload) )
        print('send pong')
        
    def recv_ping(self, payload):
        self.send_pong(payload)
        
    def recv_addr(self, payload):
        count, payload = read_var_int(payload)
        
        for i in range(count):
            data, payload = payload[:30], payload[30:]
            address, services, timestamp = deserialize_network_address( data, with_timestamp=True)
            if address not in self.peer_list:
                self.peer_list.append( address )
    
    def recv_feefilter(self, payload):
        pass
    
    def recv_inv(self, payload):
        pass
    
    def recv_reject(self, payload):
        pass
    
    def recv_sendcmpct(self, payload):
        pass
    
    def recv_sendheaders(self, payload):
        pass
    
    def send_tx(self, payload):
        self.outgoing_data_queue.append( wrap_network_message("tx", payload) )
    
    def recv_tx(self, payload):
        pass
        
        
        
    


