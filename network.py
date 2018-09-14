#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import random

import collections
import json
import socket
import threading

from util import (read_bytes, var_int, read_var_int)
from crypto import dsha256, getrandrange
from blockchain import (BlockHeader, Blockchain)
from inventory import InventoryVector

from constants import *

class NetworkError(Exception):
    '''Exception used for Network errors.'''

def serialize_network_address(netaddr, with_timestamp=True):
    ''' Serializes an address transmitted on the network. 
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
        print("Network address should be 30-byte long")
        raise NetworkError("Network address should be 30-byte long") 
    elif not with_timestamp and len(data) != 26:
        print("Network address should be 26-byte long")
        raise NetworkError("Network address should be 26-byte long")
    
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
    datacpy = data
    
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
    except Exception as e:
        print(e)
    
    length, data = read_bytes(data, 4, int, 'little')
    if (len(data) - 4) < length:
        return command, None, length, datacpy
    
    checksum, data = read_bytes(data, 4, bytes, 'big')
    payload, data = read_bytes(data, length, bytes, 'big')
    assert checksum == dsha256( payload )[:4]
    
    return command, payload, length, data



class Network(threading.Thread):
    ''' Network manager. '''
    
    TX_RELAY = False
    MAX_MESSAGE_SIZE = 1 << 20 # 1 MiB
    MAX_PEERS = 10
    MAX_PEER_ADDRESSES = 100
    
    BLOCKCHAIN_SYNC_WAIT_TIME = 5
    HEADERS_REQUEST_TIMEOUT = 25

    def __init__(self, user_agent="slwallet"):
        threading.Thread.__init__(self)
        self.user_agent = "/{}/".format(user_agent).replace(" ", ":")
        self.peer_list = self.load_peer_list() # TODO: what if the file does not exist?
        assert self.peer_list[0]['port'] == Constants.DEFAULT_PORT
        self.peers = [Peer(self, peer_address) for peer_address in self.peer_list[:self.MAX_PEERS]]
        
        self.txdb = self.load_transaction_database() # TODO: what if the file does not exist?
        print(self.txdb)
        
        # Blockchain
        self.blockchain = Blockchain.load()
        self.block_height = self.blockchain.get_height()
        print("  Network block height", self.block_height)
        self.blockchain_sync_lock = threading.Lock()
        self.initial_blockchain_sync = True
        
        # Inventory
        # TODO: do it in inventory.py? 
        self.inventory = []
        for txid in self.txdb:
            self.inventory.append( InventoryVector.from_tx_id( txid ) )
        self.inv_lock = threading.Lock()
                
        
        # Listen address
        self.listen_address = None
        
    def load_peer_list(self, filename="peers.json"):
        with open(filename, 'r') as f:
            return json.load(f)
        
    def save_peer_list(self, filename="peers.json"):
        with open(filename, 'w') as f:
            json.dump(self.peer_list, f, ensure_ascii=False, indent=4)
            
    def load_transaction_database(self, filename="txdb.json"):
        with open(filename, 'r') as f:
            return json.load(f)
        
    def save_transaction_database(self, filename="txdb.json"):
        with open(filename, 'w') as f:
            json.dump(self.txdb, f, ensure_ascii=False, indent=4)

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
        self.save_transaction_database()
        self.blockchain.save()
    
    def run(self):
        self.running = True
        while self.running:            
            #if not any( [p.is_alive() for p in self.peers] ):
            if all( [p.state == 'dead' for p in self.peers] ):
                print("NETWORK dead")
                break
            
            # Initial blockchain synchronization
            if self.initial_blockchain_sync:
                self.request_headers()
            
            time.sleep(0.01)
            
    # TODO: manage requests for block headers, transactions and blocks (merkleblock?)
    
    def request_headers(self):
        now = time.time()
        
        # TODO: wait for peer to start
        
        if all([ (p.block_height < self.block_height) for p in self.peers ]):
            self.initial_blockchain_sync = False
        
        if not any( [p.headers_request for p in self.peers] ):
            self.peers[0].headers_request = True
            self.peers[0].headers_request_time = now
        
        for p in self.peers:
            if p.headers_request:
                
                # Wait for a bit before requesting from peer
                if (now - p.handshake_time) < self.BLOCKCHAIN_SYNC_WAIT_TIME:
                    return
                
                # Timeout or block height
                if ((now - p.headers_request_time) > self.HEADERS_REQUEST_TIMEOUT) | (p.block_height < self.block_height):
                    p.headers_request = False
                    p.headers_request_time = 0
                    next_peer = self.peers[(self.peers.index( p ) + 1) % len(self.peers)]
                    next_peer.headers_request = True
                    next_peer.headers_request_time = now
                
                break
                
                    
        
        
        
    #def request_headers(self, peer):
        #peer.headers_request = True 
        
    
    # TODO: Discriminate between unsolicited headers and requests?
    def received_headers(self, peer, headers):
        assert peer in self.peers
        
        if not peer.headers_request:
            # Unsolicited headers or timed out
            return
        
        with self.blockchain_sync_lock:
            try:
                self.blockchain.add_headers( headers )
            except Exception as e:
                print(e)
                return False
            else:
                self.block_height = self.blockchain.get_height()
                best_height = self.peers_best_height()
                print("block height: {:d} / {:d} ({:.2f} %)".format(self.block_height, best_height, 
                      self.block_height / best_height * 100 ))
        
        peer.headers_request = False
        peer.headers_request_time = 0
        next_peer = self.peers[(self.peers.index( peer ) + 1) % len(self.peers)]
        next_peer.headers_request = True
        next_peer.headers_request_time = time.time()
        
        
            
    def request_tx(self, peer, txid):
        pass
    
    def received_tx(self, tx):
        txid = tx.txid()
        if txid not in self.inventory:
            self.inventory.append( txid )
            self.txdb = tx.serialize().hex()
            
    def peers_best_height(self):
        return max([peer.block_height for peer in self.peers])
    
    
        
    
    # TODO: peer discrimination (good peer, bad peer, add peer, delete peer)
    
    def add_peer_address(self, peer_address):
        pass
    
    def update_peer_address(self, peer_address):
        pass
    
    def delete_peer_address(self, peer_address):
        pass
    
    # TODO: listening socket
    
    # TODO: broadcast_transaction

class Peer(threading.Thread):
    ''' Peer manager. Manages connexion to network peer.'''
    
    def __init__(self, network, peer_address):
        threading.Thread.__init__(self)
        self.network = network
        self.address = peer_address
        self.sock = None
        
        # temporary...
        self.steps = 0
    
    def start(self):
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
            except Exception as e:
                print(e)
                break
            time.sleep(0.1)
        print("{} stopped running".format(self.address['host']))
    
    def step(self):
        # temporary...
        if (self.steps % 30) == 0:
            #print( "{}: {}".format(self.address['host'], self.state) )
            print( " ", self.headers_request )
        self.steps += 1
        
        if self.state == 'init':
            self.data_buffer = bytes()
            self.outgoing_data_queue = collections.deque()
            
            self.sent_version = False
            self.peer_verack = 0
            self.handshake_time = None
            
            self.block_height = 0
            self.sync_time = 0
            self.headers_request = False
            self.headers_request_time = 0
            self.headers_request_in_progress = False
            
            self.recvheaders = False
            self.sendheaders = False
            self.sendcmpct = False
            
            if self.sock == None:
                if self.make_connexion():
                    self.state = 'connected'
                    self.send_version()
                    
        elif self.state == 'connected':
            self.handle_outgoing_data()
            self.handle_incoming_data()
            self.handle_blockchain_sync()
            self.handle_inventory()
            
            
            
        elif self.state == 'dead':
            self.close_connexion()
            self.address['time'] = time.time()
            self.running = False
        
    def make_connexion(self):
        print("making connexion to {}".format(self.address['host']))
        
        for res in socket.getaddrinfo(self.address['host'], self.address['port'], socket.AF_UNSPEC, socket.SOCK_STREAM):
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
            
    def get_address(self):
        return self.address
    
    #def get_next_peer(self):
        #peers = self.network.peers
        #return peers[(peers.index( self ) + 1) % len(peers)]
    
    def handle_command(self, command, payload):
        print("{} handle command: {}".format(self.address['host'], command))
        if self.peer_verack < 2 and command not in ('version', 'verack'):
            raise NetworkError("invalid command")
        try:
            cmd = getattr(self, 'recv_' + command)
        except AttributeError:
            return
        cmd(payload)
            
    def handle_incoming_data(self):
        try:
            data = self.sock.recv(4096)
        except ConnectionResetError:
            data = bytes()
        except socket.timeout:
            # No new data
            return

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
        
    def handle_blockchain_sync(self):
        now = time.time()
        
        # handshake not done
        if self.handshake_time is None:
            return
        
        # just once...
        if not self.recvheaders:
            self.send_sendheaders()
            self.recvheaders = True
            self.send_feefilter()
            #if self.address['host'] == "176.9.7.168":
                #peer_addresses = self.network.peer_list
                #random.shuffle( peer_addresses )
                #peer_addresses = peer_addresses[:10]
                #self.send_addr( peer_addresses )
        
        if self.headers_request:
            with self.network.blockchain_sync_lock:
                block_locators = self.network.blockchain.get_block_locators()
                self.send_getheaders(block_locators)
    
    def handle_inventory(self):
        pass
        
    def send_version(self):
        # Version
        print("send version to {}".format(self.address['host']))
        version = Constants.PROTOCOL_VERSION.to_bytes(4, 'little')
        my_services = Constants.NODE_NONE + Constants.NODE_BITCOIN_CASH #SPV
        services = my_services.to_bytes(8, 'little')
        timestamp = int( time.time() ).to_bytes(8, 'little')
        addr_recv = serialize_network_address(self.address, with_timestamp=False)
        my_network_address = {'host':"127.0.0.1", 'port':8333, 'services':my_services}
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
            self.version, payload = read_bytes(payload, 4, int, 'little')
            self.services, payload = read_bytes(payload, 8, int, 'little')
            self.time, payload = read_bytes(payload, 8, int, 'little')
            addr_recv, payload = read_bytes(payload, 26, bytes, 'big')
            my_network_address = deserialize_network_address(addr_recv, with_timestamp=False)
            addr_trans, payload = read_bytes(payload, 26, bytes, 'big')
            peer_network_address = deserialize_network_address(addr_trans, with_timestamp=False)
            nonce, payload = read_bytes(payload, 8, int, 'little')
            peer_user_agent_size, payload = read_var_int(payload)
            peer_user_agent, payload = read_bytes(payload, peer_user_agent_size, bytes, 'big')
            self.block_height, payload = read_bytes(payload, 4, int, 'little')
            relay, payload = read_bytes(payload, 1, int, 'little')
            assert payload == bytes()
        except:
            self.state = 'dead'
            return
        
        print(" Peer address: {}\n Services: {:d}\n User Agent: {}".format(peer_network_address['host'], peer_network_address['services'], peer_user_agent.decode('ascii')) )
        
        self.send_verack()
        self.peer_verack += 1

        if not self.sent_version:
            self.send_version()
        
        if self.peer_verack == 2:
            self.handshake_time = time.time()
            print("{} handshake done".format(self.address['host']))
        
    def send_verack(self):
        # Version acknowledgment.
        print("send verack to {}".format(self.address['host']))
        self.outgoing_data_queue.append( wrap_network_message("verack", bytes()) )
    
    def recv_verack(self, payload):
        assert payload == bytes()
        self.peer_verack += 1
        if self.peer_verack == 2:
            self.handshake_time = time.time()
            print("handshake done with {}".format(self.address['host']))
            
    def send_ping(self):
        nonce = getrandrange( 1 << 64 ).to_bytes(8, 'little')
        self.outgoing_data_queue.append( wrap_network_message("ping", payload) )
        print("send ping to {}".format(self.address['host']))
        
    def recv_ping(self, payload):
        self.send_pong(payload)
    
    def send_pong(self, payload):
        self.outgoing_data_queue.append( wrap_network_message("pong", payload) )
        print("send pong to {}".format(self.address['host']))
    
    def recv_pong(self, payload):
        pass
    
    def send_getaddr(self):
        # Ask information about known active peers.
        self.outgoing_data_queue.append( wrap_network_message("getaddr", bytes()) )
        print("send getaddr to {}".format(self.address['host']))
    
    def recv_getaddr(self, payload):
        assert payload == bytes()
        peer_addresses = self.network.peer_list
        random.shuffle( peer_addresses )
        peer_addresses = peer_addresses[:10]
        self.send_addr( peer_addresses )
    
    def send_addr(self, peer_addresses):
        count = var_int( len( peer_addresses ) )
        payload = count + bytes().join( serialize_network_address( pa, with_timestamp=True ) for pa in peer_addresses )
        self.outgoing_data_queue.append( wrap_network_message("addr", bytes()) )
        print("send addr to {}".format(self.address['host']))
        print( " ", payload.hex() )
        
    def recv_addr(self, payload):
        count, payload = read_var_int(payload)
        
        for i in range(count):
            data, payload = read_bytes(payload, 30, bytes, 'big')
            address = deserialize_network_address( data, with_timestamp=True )

            if not any([address['host'] == na['host'] for na in self.network.peer_list]) & (address['host'] != "") & (address['port'] == Constants.DEFAULT_PORT) & (len(self.network.peer_list) < self.network.MAX_PEER_ADDRESSES ):
                self.network.peer_list.append( address )
                print("New peer address: {}".format(address['host']) )
        assert payload == bytes()
    
    def send_feefilter(self):
        feerate = Constants.FEE_RATE * 1000
        my_feerate = feerate.to_bytes(8, 'little')
        self.outgoing_data_queue.append( wrap_network_message("feefilter", my_feerate) )
        print("send feefilter to {}".format(self.address['host']))
    
    def recv_feefilter(self, payload):
        self.peer_feerate, payload = read_bytes(payload, 8, int, 'little')
        print("feerate (sat/kB)", self.peer_feerate)
        
    # Inventory
        
    def send_inv(self, invs):
        # Advertise our knowledge of one or more objects.
        payload = var_int( len(invs) ) + bytes().join( inv.serialize() for inv in invs )
        self.outgoing_data_queue.append( wrap_network_message("inv", payload) )
        print("send inv to {}".format(self.address['host']))
    
    def recv_inv(self, payload):
        count, payload = read_var_int(payload)
        
        for i in range(count):
            data, payload = read_bytes(payload, 36, bytes, 'big')
            inv = InventoryVector.from_serialized( data )
            # TODO get data if we need it
            #   invs.append( inv )
            # self.send_getdata( invs )
            print(inv)
            
    def send_getdata(self, invs):
        payload = var_int( len(invs) ) + bytes().join( inv.serialize() for inv in invs )
        self.outgoing_data_queue.append( wrap_network_message("getdata", payload) )
        print("send getdata to {}".format(self.address['host']))

    
    def recv_getdata(self, payload):
        count, payload = read_var_int(payload)
        
        for i in range(count):
            data, payload = read_bytes(payload, 36, bytes, 'big')
            inv = InventoryVector.from_serialized( data )
            if inv in self.inventory:
                if inv.is_tx():
                    try:
                        tx = self.txdb[inv.get_id()]
                    except:
                        raise NetworkError("cannot retrieve transaction")
                    else:
                        self.send_tx( bytes.fromhex( tx ) )
                    
    
    def send_notfound(self):
        pass
    
    def recv_notfound(self, payload):
        pass
    
    # Headers
    
    def send_sendheaders(self):
        self.outgoing_data_queue.append( wrap_network_message("sendheaders", bytes()) )
        print("send sendheaders to {}".format(self.address['host']))
    
    def recv_sendheaders(self, payload):
        # Upon receipt of this message, the node is be permitted, but not
        # required, to announce new blocks by headers command (instead of 
        # inv command).
        self.sendheaders = True
    
    def send_getheaders(self, block_locators):
        version = Constants.PROTOCOL_VERSION.to_bytes(4, 'little')
        length_block_locators = var_int( len( block_locators ) )
        ser_block_locators = bytes().join( bl[::-1] for bl in block_locators )
        stop = bytes(32)
        
        payload = version + length_block_locators + ser_block_locators + stop
        self.outgoing_data_queue.append( wrap_network_message("getheaders", payload) )
        print("send getheaders to {}".format(self.address['host']))
        
    def recv_getheaders(self, payload):
        pass
    
    
    
    def recv_headers(self, payload):
        count, payload = read_var_int(payload)
        assert count <= 2000
        
        headers = []            
        for i in range(count):
            hdr, payload = read_bytes(payload, Constants.BLOCKHEADER_SIZE, bytes, 'big')
            headers.append(hdr)
            tx_count, payload = read_var_int(payload)
            assert tx_count == 0
        
        self.network.received_headers(self, headers)

        #if self.network.received_headers(self, headers):
            #self.sync_time = time.time()
            #self.headers_request_in_progress = False
            
            ## We request headers from another peer
            #next_peer = self.get_next_peer()
            #self.network.request_headers( next_peer )
        #else:
            #print("recv_headers error")
            
    # Blocks
    
    def send_getblocks(self):
        pass
    
    def recv_get_blocks(self, payload):
        pass
    
    def send_block(self):
        pass
    
    def recv_block(self, payload):
        pass
            
    def send_sendcmpct(self):
        pass
            
    def recv_sendcmpct(self, payload):
        # TODO: read integers
        # _, payload = read_bytes(payload, 1, int, 'little')
        # _, payload = read_bytes(payload, 8, int, 'little')
        # assert payload == bytes()
        #print(" sendcmpct", payload.hex())
        pass#self.sendcmpct = True
        
    # Bloom Filtering for Simplified Payment Verification
    
    def send_filterload(self):
        pass
    
    def recv_filterload(self, payload):
        pass
    
    def send_filteradd(self):
        pass
    
    def recv_filteradd(self, payload):
        pass
    
    def send_filterclear(self):
        pass
    
    def recv_filterclear(self, payload):
        pass
    
    def send_merkleblock(self):
        pass
    
    def recv_merkleblock(self, payload):
        pass
        
    # Transactions
    
    def send_mempool(self):
        # Requests peer mempool transactions
        pass
    
    def recv_mempool(self, payload):
        pass
    
    def send_getblocktxn(self):
        pass
    
    def recv_getblocktxn(self, payload):
        pass
    
    def send_blocktxn(self):
        pass
    
    def recv_blocktxn(self, payload):
        pass
    
    def send_tx(self, payload):
        # Transaction message: version - inputs - outputs - locktime
        # See transaction.py for more details
        self.outgoing_data_queue.append( wrap_network_message("tx", payload) )
    
    def recv_tx(self, payload):
        tx = Transaction.from_serialized( payload )
        
        # TODO: conditions to accept the transaction
        if tx.txid() in self.tx_requests:
            self.network.received_tx( tx )
        else:
            print("unsolicited transaction from {}".format(self.address['host']) )
        
    def send_reject(self):
        pass
    
    def recv_reject(self, payload):
        length_msg, payload = read_var_int(payload)
        raw_msg, payload = read_bytes(payload, length_msg, bytes, 'big')
        msg = raw_msg.decode('ascii')
        ccode, payload = read_bytes(payload, 1, int, 'little')
        length_reason, payload = read_var_int(payload)
        raw_reason, payload = read_bytes(payload, length_reason, bytes, 'big')
        reason = raw_reason.decode('utf-8')
        data = payload.hex()
        
        print("{} reject {}: {}, {} {}".format( self.address['host'], msg, 
        { Constants.REJECT_MALFORMED: "malformed",
          Constants.REJECT_INVALID: "invalid",
          Constants.REJECT_OBSOLETE: "obsolete",
          Constants.REJECT_DUPLICATE: "duplicate",
          Constants.REJECT_NONSTANDARD: "non standard",
          Constants.REJECT_DUST: "dust",
          Constants.REJECT_INSUFFICIENTFEE: "insufficient fee",
          Constants.REJECT_CHECKPOINT: "checkpoint" }[ccode],
        reason, data) )
    
    def __str__(self):
        return self.__repr__()
    
    def __repr__(self):
        return "<Peer {host}/{port}>".format(**self.address)

    