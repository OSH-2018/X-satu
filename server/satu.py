#/usr/bin/env python3

import asyncio
import sys
import json
import multiprocess as mp

class ServerProtocol:
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        message = data.decode()
        ret = bytes(chr(len(message)%128)+'\n', "ascii")
        print('Received %r from %s' % (data, addr))
        #self.deal(self.config, data)
        #self.clients.get(addr).store(data)
        #self.transport.sendto(ret, addr)

class Server:
    def __init__(self, config):
        self.config = config
        #self.deal = deal
        self.loop = asyncio.get_event_loop()
        self.listen = self.loop.create_datagram_endpoint(ServerProtocol, local_addr=(self.config['addr'], self.config['port']))
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
