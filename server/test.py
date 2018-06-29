#!/usr/bin/env python3
import socket

UDP_IP = "::" # = 0.0.0.0 u IPv4
UDP_PORT = 54321

sock = socket.socket(socket.AF_INET6, # Internet
		     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    print("received message:", data)
    print("intentionally no reply...")

    data, addr = sock.recvfrom(1024)
    print("received message:", data)
    print("this time give reply...")
    sock.sendto(b'ab', addr)
