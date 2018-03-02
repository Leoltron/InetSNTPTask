# !/usr/bin/env python3
import datetime
from socket import socket, AF_INET, SOCK_DGRAM

import sntp_util
from sntp_util import LI, Mode, SNTPMessage


class SNTPLiarServer:
    server_socket = None

    def __init__(self, hostname, port=123, lying_seconds=0):
        self._hostname = hostname
        self._port = port
        self._lying_timedelta = datetime.timedelta(seconds=lying_seconds)

    def start(self):
        self.server_socket = udp_socket = socket(AF_INET, SOCK_DGRAM)
        udp_socket.bind((self._hostname, self._port))
        print('Current lie is "'+str(self._lying_timedelta)+'"')
        print("Started server at ", self._hostname + ":" + str(self._port))
        try:
            while True:
                conn, address = udp_socket.recvfrom(1024)
                self.handle_message(conn, address)
        finally:
            print("Stopping...")
            udp_socket.close()

    def handle_message(self, conn: bytes, address):
        log_string = "Received: message from " + str(address) + ": "
        try:
            sntp_request = SNTPMessage.from_bytes(conn, [Mode.CLIENT])
            rcv_ts = datetime.datetime.utcnow()+self._lying_timedelta

            answer = self.generate_prime_ref_server_answer(rcv_ts, conn[40:48])
            #answer =  sntp_util.send_udp_message_and_get_reply(conn, 123, "time.windows.com")
            #answer = SNTPMessage.from_bytes(answer,[Mode.SERVER]).to_bytes()
            self.server_socket.sendto(answer, address)
        except ValueError as e:
            log_string += str(e)
        else:
            log_string += "OK"
        print(log_string)

    def generate_prime_ref_server_answer(self, receive_ts, origin_ts:bytes) -> SNTPMessage:
        current_time = datetime.datetime.utcnow() + self._lying_timedelta
        result= SNTPMessage(li=LI.NO_WARNING,
                           version=4,
                           mode=Mode.SERVER,
                           stratum=1,
                           poll=4,
                           precision=-20,
                           root_delay=0.1,
                           root_dispersion=0.01,
                           ref_id=b"LOCL",
                           ref_ts=current_time,
                           rcv_ts=receive_ts,
                           transmit_ts=current_time).to_bytes()
        result[24:32] = origin_ts
        return result
