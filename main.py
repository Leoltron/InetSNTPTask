# !/usr/bin/env python3
import os.path

from sntp_server import SNTPLiarServer


def main(config_file):
    if not os.path.isfile(config_file):
        print('Error: file "' + os.path.abspath(config_file) + '" not found.')
        return

    try:
        with open(config_file)as f:
            lie_seconds = int(f.readline())
        SNTPLiarServer("localhost", lying_seconds=lie_seconds,
                       port=123).start()
    except Exception as e:
        print("An unexpected error occurred: " + str(e))


if __name__ == '__main__':
    main("time_offset.txt")
