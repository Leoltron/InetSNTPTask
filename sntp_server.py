# !/usr/bin/env python3
import datetime
from socket import socket, AF_INET, SOCK_DGRAM


class SNTPLiarServer:
    def __init__(self, hostname, lying_seconds=0):
        self._hostname = hostname
        self._lying_seconds = lying_seconds

    def start(self):
        udp_socket = socket(AF_INET, SOCK_DGRAM)
        udp_socket.bind((self._hostname, 123))
        try:
            while True:
                print("Waiting for message...")
                conn, addr = udp_socket.recvfrom(1024)
                self.handle_message(conn, addr)
        finally:
            print("Stopping...")
            udp_socket.close()

    def handle_message(self, conn, addr):
        print("Received:\n\t"+str(conn)+"\n\t"+str(addr))
