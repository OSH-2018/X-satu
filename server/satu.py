#!/usr/bin/env python3

import sys
import socket
import json


class ClientManager:
    def __init__(self, prefix):
        self.prefix = prefix
        self.clients = {}

    def get(self, addr):
        if addr not in self.clients:
            client = Client(addr, str(addr), self.prefix)
            self.clients[addr] = client
        return self.clients[addr]

    def close(self):
        for client in self.clients:
            client.close()
        clients = {}


class Client:
    def __init__(self, addr, name, prefix):
        self.addr = addr
        self.name = name
        self.prefix = prefix
        self.stream_file = None

    def get_stream_file(self):
        if self.stream_file:
            return self.stream_file
        self.stream_file = open('%s' % self.prefix + '.%s' % self.name, 'wb', buffering=0)
        return self.stream_file

    def store(self, data):
        self.get_stream_file().write(data)

    def close(self):
        self.stream_file.close()


class Server:
    def __init__(self, config):
        self.clients = ClientManager(config['prefix'])
        self.udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpsock.bind((config['addr'], config['port']))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.clients.close()

    def run(self):
        try:
            while True:
                data, addr = self.udpsock.recvfrom(2048)
                print('received: ', data, 'from', addr)
                self.clients.get(addr).store(data)
        except KeyboardInterrupt:
            exit(0)


def main(args):
    config = {}
    with open('config.json', 'r') as f:
        config = json.load(f)
    server = Server(config)
    server.run()

if __name__ == '__main__':
    main(sys.argv)
else:
    raise ImportError("satu.py can't be imported")
