#!/usr/bin/env python3

import sys
import socket
import json
import datetime as dt
import multiprocessing as mp
import tkinter as tk
from tkinter import messagebox


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
        self.clients = {}

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
        self.config = config
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
                #self.udpsock.sendto(b'test', addr)
                self.udpsock.sendto(bytes(chr(len(data)%128)+'\n', "ascii"), addr)
                print('received: ', data, 'from', addr)
                self.deal(data)
                self.clients.get(addr).store(data)
        except KeyboardInterrupt:
            exit(0)
    
    def deal(self, data):
        """the function user use to deal with data"""
        if 'up' in self.config:
            try:
                if int(data) >= self.config['up']:
                    root = tk.Tk()
                    root.withdraw()
                    messagebox.showinfo('warning', 'temperature too high!')
                    print("warning! temperature too high!")
            except ValueError:
                print("please enter a number!")


def main(args):
    config = []
    processes = []
    with open('config.json', 'r') as f:
        config = json.load(f)
        #pool = ThreadPool(len(config))
        for line in config:
            server = Server(line)
            pro = mp.Process(target=server.run)
            processes.append(pro)
        
        for p in processes:
            p.start()

if __name__ == '__main__':
    main(sys.argv)
else:
    raise ImportError("satu.py can't be imported")
