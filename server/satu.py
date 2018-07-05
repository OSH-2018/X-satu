#/usr/bin/env python3

import asyncio
import sys
import json
import datetime as dt
import multiprocess as mp
import tkinter as tk
from tkinter import messagebox

class ServerProtocol:
    def __init__(self, config, deal):
        self.config = config
        self.stream_file = None
        self.format = 'stream'
        self.deal = deal

    def connection_made(self, transport):
        self.transport = transport

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

    def get_stream_file(self):
        if self.stream_file:
            return self.stream_file
        self.stream_file = open(self.format, 'ab', buffering=0)
        return self.stream_file

    def datagram_received(self, data, addr):
        self.format = self.ename(addr)
        #message = data.decode()
        self.deal(self.config, data)
        ret = bytes(chr(len(data)%128)+'\n', "ascii")
        self.transport.sendto(ret, addr)

        print('Received %r from %s' % (data, addr))
        self.get_stream_file().write(data)

class Server:
    def __init__(self, config, deal):
        self.loop = asyncio.get_event_loop()
        self.listen = self.loop.create_datagram_endpoint(lambda: ServerProtocol(config, deal), local_addr=(config['addr'], config['port']))
        self.transport, self.protocol = self.loop.run_until_complete(self.listen)

    def __enter__(self):
        print("Starting UDP server")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.transport.close()
        self.loop.close()
    # One protocol instance will be created to serve all client requests

    def run(self):
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            pass

def demo(config, data):
    """the function user use to deal with data"""
    if 'up' in config:
        try:
            if int(data) >= config['up']:
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
            server = Server(line, demo)
            pro = mp.Process(target=server.run)
            processes.append(pro)
        
        for p in processes:
            p.start()

if __name__ == '__main__':
    main(sys.argv)
else:
    raise ImportError("satu.py can't be imported")
