#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

import collections
import json
import socket
import threading

from util import (read_bytes, read_var_int)
from crypto import dsha256, getrandrange
from inventory import Inventory

from constants import *

SPV_SERVICES = 0
RELAY = False

DEFAULT_IPV6_ADDRESS = 0xffff7f000001 #127.0.0.1

class NetworkError(Exception):
    '''Exception used for Network errors.'''

def serialize_network_address(netaddr, with_timestamp=True):
    ''' Serializes an address transitted on the network. 
    netaddr (dict): network address (host, port, services, time)
    with_timestamp (bool): no timestamp in version message '''
    try:
        # IPv6
        address = socket.inet_pton(socket.AF_INET6, netaddr['host'])
    except:
        # IPv4
        address = (bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]) 
                   + socket.inet_pton(socket.AF_INET, netaddr['host']))
    port = Constants.DEFAULT_PORT.to_bytes(2,'big')
    services = netaddr['services'].to_bytes(8, 'little')
    if with_timestamp:
        timestamp = netaddr['time'].to_bytes(4, 'little')
        return timestamp + services + address + port
    else:
        return services + address + port

def deserialize_network_address( data, with_timestamp=True ):
    if with_timestamp and len(data) != 30:
        raise NetworkError('Network address should be 30-byte long') 
    elif not with_timestamp and len(data) != 26:
        raise NetworkError('Network address should be 26-byte long')
    
    netaddr = {}
    if with_timestamp:
        netaddr['time'], data = read_bytes(data, 4, int, 'little')
    
    netaddr['services'], data = read_bytes(data, 8, int, 'little')
    address, data = read_bytes(data, 16, bytes, 'big')
    if address[0:-4] == bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]):
        # IPv4
        netaddr['host'] = socket.inet_ntop(socket.AF_INET, address[-4:])
    else:
        # IPv6
        netaddr['host'] = socket.inet_ntop(socket.AF_INET6, address)
    netaddr['port'], data = read_bytes(data, 2, int, 'big')
    
    return netaddr
 
def wrap_network_message( command, payload ):
    ''' Message Structure for Bitcoin Protocol.
    command (str) : command (e.g. "version")
    payload (bytes) : actual data '''
    magic = Constants.NETWORK_MAGIC.to_bytes(4,'little')
    cmdb = command.encode('ascii')
    cmd = cmdb + ( ( 12 - len(cmdb) ) * b"\00" )
    length = len(payload).to_bytes(4, 'little')
    checksum = dsha256( payload )[:4]
    return magic + cmd + length + checksum + payload

def unwrap_network_message( data ):
    if len(data) < 24:
        return None, None, None, data
    
    magic, data = read_bytes(data, 4, int, 'little')
    assert magic == Constants.NETWORK_MAGIC
    
    cmd, data = read_bytes(data, 12, bytes, 'big')
        
    i = 0
    while cmd[i] != 0 and i < 12:
        i += 1
    try: 
        command = cmd[:i].decode('ascii')
    except UnicodeDecodeError:
        raise NetworkError("Invalid command encoding")
    
    length, data = read_bytes(data, 4, int, 'little')
    if (len(data) - 4) < length:
        return command, None, length, data
    
    checksum, data = read_bytes(data, 4, bytes, 'big')
    payload, data = read_bytes(data, length, bytes, 'big')
    assert checksum == dsha256( payload )[:4]
    
    return command, payload, length, data



class Network(threading.Thread):
    ''' Network manager. '''
    
    SERVICES = 0
    TX_RELAY = False
    MAX_MESSAGE_SIZE = 1 << 20 # 1 MiB
    
    def __init__(self, block_height, user_agent="slwallet"):
        threading.Thread.__init__(self)
        self.user_agent = "/{}/".format(user_agent).replace(" ", ":")
        self.peer_list = self.load_peer_list()
        assert self.peer_list[0]['port'] == Constants.DEFAULT_PORT
        self.block_height = block_height
        self.peers = [Peer(self, self.peer_list[0])]
        
        # Inventory
        self.inventory = collections.deque()
        self.inventory_items = {}
        
        # Blockchain sync
        self.blockchain_sync_lock = threading.Lock()
        
        # Listen address
        self.listen_address = None
        
    def load_peer_list(self, filename="peers.json"):
        with open(filename, 'r') as f:
            return json.load(f)
        
    def save_peer_list(self, filename="peers.json"):
        with open(filename, 'w') as f:
            json.dump(self.peer_list, f, ensure_ascii=False)

    def start(self):
        self.running = False
        for p in self.peers:
            p.start()
        threading.Thread.start(self)
        while not self.running:
            pass
        
    def shutdown(self):
        for p in self.peers:
            p.shutdown()
        self.running = False
        self.save_peer_list()
    
    def run(self):
        self.running = True
        while self.running:            
            #if not any( [p.is_alive() for p in self.peers] ):
            if all( [p.state == 'dead'] ):
                print("NETWORK dead")
                break
            time.sleep(0.01)


class Peer(threading.Thread):
    ''' Peer manager. Manages connexion to network peer.'''
    
    def __init__(self, network, peer_address):
        threading.Thread.__init__(self)
        self.network = network
        self.peer_address = peer_address
        self.sock = None
    
    def start(self):
        print("start")
        self.running = False
        threading.Thread.start(self)
        while not self.running:
            pass
        
    def shutdown(self):
        self.running = False
        
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
            
            if self.sock == None:
                if self.make_connexion():
                    self.state = 'connected'
                    print(self.state)
                    self.send_version()
                    
        elif self.state == 'connected':
            print(self.state)
            self.handle_outgoing_data()
            self.handle_incoming_data()
        elif self.state == 'dead':
            print("{} dead".format(self.peer_address['host']))
            self.close_connexion()
            self.running = False
        
    def make_connexion(self):
        print("making connexion to {}".format(self.peer_address['host']))
        
        for res in socket.getaddrinfo(self.peer_address['host'], self.peer_address['port'], socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            
            # TODO: IPv6 support
            if socktype == socket.AF_INET6:
                # No IPv6 support
                continue
            
            try:
                self.sock = socket.socket(af, socktype, proto)
            except socket.error as msg:
                print("socket.socket():", msg)
                self.sock = None
                continue
            try:
                self.sock.settimeout(5)
                self.sock.connect( sa )
            except socket.error as msg:
                print("sock.connect():", msg)
                self.sock.close()
                self.sock = None
                continue
            break
        
        if self.sock == None:
            self.state = 'dead'
            return False
        else:
            self.sock.settimeout(0.1)
            return True        
    
    def close_connexion(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            
    def handle_incoming_data(self):
        try:
            data = self.sock.recv(4096)
        except ConnectionResetError:
            data = bytes()
        except sock.timeout:
            # No new data
            return
        
        print("incoming data from {}  {}".format(self.peer_address['host'], data.hex() ))
        
        if len(data) == 0: # lost connexion
            self.state = 'dead'
            print("len(data) == 0")
            return
        
        self.data_buffer += data
        while self.state != 'dead':
            command, payload, length, self.data_buffer = unwrap_network_message( self.data_buffer )
            
            if length != None and length > self.network.MAX_MESSAGE_SIZE:
                self.state = 'dead'
                print("length > self.network.MAX_MESSAGE_SIZE")
                break
            
            if payload == None:
                break
            
            self.handle_command(command, payload)

    def handle_outgoing_data(self):
        while len(self.outgoing_data_queue) > 0:
            q = self.outgoing_data_queue.popleft()
            try:
                r = self.sock.send(q)
                if r < len(q):
                    self.outgoing_data_queue.appendleft(q[r:])
                    return
            except (ConnectionAbortedError, OSError) as msg:
                print(msg)
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
        print("send version to {}".format(self.peer_address['host']))
        version = Constants.PROTOCOL_VERSION.to_bytes(4, 'little')
        services = self.network.SERVICES.to_bytes(8, 'little')
        timestamp = int( time.time() ).to_bytes(8, 'little')
        addr_recv = serialize_network_address(self.peer_address, with_timestamp=False)
        my_network_address = {'host':"127.0.0.1", 'port':8333, 'services':0}
        addr_trans = serialize_network_address(my_network_address, with_timestamp=False)
        nonce = getrandrange( 1 << 64 ).to_bytes(8, 'little')
        user_agent = self.network.user_agent.encode('ascii')
        user_agent_bytes = bytes([len(user_agent)])
        start_height = self.network.block_height.to_bytes(4, 'little')
        relay = bytes([self.network.TX_RELAY])
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
            addr_recv, payload = read_bytes(payload, 26, bytes, 'big')
            my_network_address = deserialize_network_address(addr_recv, with_timestamp=False)
            addr_trans, payload = read_bytes(payload, 26, bytes, 'big')
            peer_network_address = deserialize_network_address(addr_trans, with_timestamp=False)
            nonce, payload = read_bytes(payload, 8, int, 'little')
            peer_user_agent_size, payload = read_var_int(payload)
            peer_user_agent, payload = read_bytes(payload, peer_user_agent_size, bytes, 'big')
            self.peer_block_height, payload = read_bytes(payload, 4, int, 'little')
            relay, payload = read_bytes(payload, 1, int, 'little')
            assert payload == bytes()
        except:
            self.state = 'dead'
            return
        
        if self.peer_block_height > self.network.block_height:
            self.network.block_height = self.peer_block_height
        
        print("Version\n Peer address: {}\n Services: {:d}\n User Agent: {}".format(peer_network_address['host'], peer_network_address['services'], peer_user_agent.decode('ascii')) )
        
        self.send_verack()
        self.peer_verack += 1

        if not self.sent_version:
            self.send_version()
        
        if self.peer_verack == 2:
            self.handshake = True
            print("handshake done with {}".format(self.peer_address['host']))
        
    def send_verack(self):
        print("send verack to {}".format(self.peer_address['host']))
        self.outgoing_data_queue.append( wrap_network_message("verack", bytes()) )
    
    def recv_verack(self, payload):
        assert payload == bytes()
        self.peer_verack += 1
        if self.peer_verack == 2:
            self.handshake = True
            print("handshake done with {}".format(self.peer_address['host']))
            
    def send_ping(self, payload=bytes()):
        self.outgoing_data_queue.append( wrap_network_message("ping", payload) )
        print('send ping to {}'.format(self.peer_address['host']))
        
    def recv_ping(self, payload):
        self.send_pong(payload)
    
    def send_pong(self, payload):
        self.outgoing_data_queue.append( wrap_network_message("pong", payload) )
        print('send pong to {}'.format(self.peer_address['host']))
    
    def recv_pong(self, payload):
        pass
        
    def recv_addr(self, payload):
        count, payload = read_var_int(payload)
        
        for i in range(count):
            data, payload = read_bytes(payload, 30, bytes, 'big')
            address = deserialize_network_address( data, with_timestamp=True )

            if not any([address['host'] == na['host'] for na in self.network.peer_list]) & (address['host'] != "") & (address['port'] == Constants.DEFAULT_PORT):
                self.network.peer_list.append( address )
                print("New IP address: {}".format(address['host']) )
        assert payload == bytes()
    
    def recv_feefilter(self, payload):
        pass
    
    def recv_inv(self, payload):
        count, payload = read_var_int(payload)
        
        for i in range(count):
            data, payload = read_bytes(payload, 30, bytes, 'big')
            inv = Inventory.deserialize( data )
            # TODO add inv to inventory
            print(inv)
    
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
    
    def __str__(self):
        return self.__repr__()
    
    def __repr__(self):
        return "<Peer {host}/{port}>".format(**self.peer_address)
    
if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
        
    #ipv6_host = "2a00:7c80:0:5d::4593"
    #port = 8333
    
    #print( socket.getaddrinfo(ipv6_host, 8333, 0, 0) )
    #res = socket.getaddrinfo(ipv6_host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    #af, socktype, proto, canonname, sa = res[0]
    #print(sa)
    
    #sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    #sock.connect((ipv6_host, port, 0, 0))
    ##sock.connect(sa)
    ##data = sock.recv(1024)
    ##print(data.hex())
    
    #time.sleep(3)
    #sock.close()
    
    ## Echo client program
    #import socket
    #import sys
    
    host = '254.50.229.190'
    port = 8333
    

    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.connect( (host, port) )
                      
    ##HOST = 'daring.cwi.nl'    # The remote host
    ##PORT = 50007              # The same port as used by the server
    #s = None
    #for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
        #af, socktype, proto, canonname, sa = res
        #try:
            #s = socket.socket(af, socktype, proto)
        #except socket.error as msg:
            #s = None
            #continue
        #try:
            #s.connect(sa)
        #except socket.error as msg:
            #s.close()
            #print(msg)
            #s = None
            #continue
        #break
    #if s is None:
        #print('could not open socket')
        #sys.exit(1)
    #s.send(b'Hello, world')
    #data = s.recv(1024)
    #s.close()
    #print('Received', repr(data))
    
    

    