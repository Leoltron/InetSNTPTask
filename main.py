# !/usr/bin/env python3
import os
from sntp_client import get_time_from
from sntp_server import SNTPLiarServer

CONFIG_FILE = "time_offset.txt"


def main():
    if not os.path.isfile(CONFIG_FILE):
        print('Error: file "' + os.path.abspath(CONFIG_FILE) + '" not found.')
        return

    with open(CONFIG_FILE)as f:
        lie_seconds = int(f.readline())
    SNTPLiarServer("10.96.19.61", lie_seconds).start()


if __name__ == '__main__':
    main()
