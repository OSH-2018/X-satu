#!/usr/bin/env python3

import sys
import socket
import json
import datetime as dt
import multiprocessing as mp


class ClientManager:
    def __init__(self, config):
        self.format = 'stream'
        self.clients = {}
        self.config = config

    def get(self, addr):
        self.format = self.ename(addr)
        if addr not in self.clients:
            client = Client(addr, self.format)
            self.clients[addr] = client
        return self.clients[addr]

    def close(self):
        for client in self.clients:
            client.close()
        clients = {}

    def ename(self, addr):
        # format the filename by format string in json
        name = ''
        _format = self.config['format']
        parts = _format.split("%")
        name += parts[0]
        for i in range(1,len(parts)):
            if parts[i][0] == '@': # address
                name += addr[0]
            elif parts[i][0] == '#': # port number
                name += str(addr[1])
            else:
                name += dt.datetime.today().strftime('%'+parts[i][0])
            name += parts[i][1:]
        return name


class Client:
    def __init__(self, addr, format):
        self.addr = addr
        self.format = format
        self.stream_file = None

    def get_stream_file(self):
        if self.stream_file:
            return self.stream_file
        self.stream_file = open(self.format, 'ab', buffering=0)
        return self.stream_file

    def store(self, data):
        self.get_stream_file().write(data)

    def close(self):
        self.stream_file.close()


class Server:
    def __init__(self, config):
        self.clients = ClientManager(config)
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
    config = []
    processes = []
    with open('config.json', 'r') as f:
        config = json.load(f)
        #pool = ThreadPool(len(config))
        for line in config:
            server = Server(line)
            pro = mp.Process(target=server.run)
            print(line)
            processes.append(pro)
        
        for p in processes:
            p.start()

if __name__ == '__main__':
    main(sys.argv)
else:
    raise ImportError("satu.py can't be imported")
