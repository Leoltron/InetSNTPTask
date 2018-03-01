# !/usr/bin/env python3
import datetime
from socket import socket, AF_INET, SOCK_DGRAM

from sntp_util import parse_sntp_message


class SNTPLiarServer:
    def __init__(self, hostname,port=123, lying_seconds=0):
        self._hostname = hostname
        self._port = port
        self._lying_seconds = lying_seconds

    def start(self):
        udp_socket = socket(AF_INET, SOCK_DGRAM)
        udp_socket.bind((self._hostname, self._port))
        print("Started server at ",self._hostname+":"+str(self._port))
        try:
            while True:
                print("Waiting for message...")
                conn, addr = udp_socket.recvfrom(1024)
                self.handle_message(conn, addr)
        finally:
            print("Stopping...")
            udp_socket.close()

    def handle_message(self, conn, addr):
        parse_sntp_message(conn)
        print("Received:\n\t"+str(conn)+"\n\t"+str(addr))
