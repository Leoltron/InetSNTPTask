# !/usr/bin/env python3
from datetime import datetime, timedelta
from socket import socket, AF_INET, SOCK_DGRAM

from sntp_message import LI, Mode, SNTPMessage


class SNTPLiarServer:
    server_socket = None

    def __init__(self, hostname, port=123, lying_seconds=0):
        self._hostname = hostname
        self._port = port
        self._lying_timedelta = timedelta(seconds=lying_seconds)

    @property
    def address(self) -> str:
        return self._hostname + ":" + str(self._port)

    def start(self):
        self.server_socket = udp_socket = socket(AF_INET, SOCK_DGRAM)
        udp_socket.bind((self._hostname, self._port))

        print('Server will lie for ' + str(self._lying_timedelta))
        print("Started server at", self.address)

        try:
            while True:
                message, address = udp_socket.recvfrom(1024)
                self.handle_message(message, address)
        finally:
            print("Stopping...")
            udp_socket.close()
            self.server_socket = None

    def handle_message(self, message: bytes, address):
        print("Received: message from " + str(address) + ": ", end='')
        try:
            receive_time = datetime.utcnow() + self._lying_timedelta
            validaton = SNTPMessage.from_bytes(message, [Mode.CLIENT])
            answer = self.get_server_answer(receive_time, message[40:48])
            self.server_socket.sendto(answer, address)
        except ValueError as e:
            print(str(e))
        else:
            print("OK")

    def get_server_answer(self,
                          receive_ts: datetime,
                          origin_ts_bytes: bytes) -> bytes:
        current_time = datetime.utcnow() + self._lying_timedelta
        result = SNTPMessage(li=LI.NO_WARNING,
                             version=4,
                             mode=Mode.SERVER,
                             stratum=1,
                             poll=4,
                             precision=-20,
                             root_delay=0,
                             root_dispersion=0,
                             ref_id=b"LOCL",
                             ref_ts=current_time,
                             rcv_ts=receive_ts,
                             transmit_ts=current_time).to_bytes()
        result[24:32] = origin_ts_bytes
        return result
