# !/usr/bin/env python3

import sntp_util
import socket


def main(tries=4, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try_ = 0
    while True:
        sock.sendto(sntp_util.form_sntp_message(mode=sntp_util.Mode.CLIENT), ("time.windows.com", 123))
        try:
            reply = sock.recv(1024)
            return reply
        except socket.timeout:
            try_ += 1
            if try_ > tries > 0:
                raise TimeoutError("Out of tries")
            print("Timeout has reached, trying again")


if __name__ == '__main__':
    main()
