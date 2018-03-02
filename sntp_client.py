# !/usr/bin/env python3

import datetime
from sntp_util import *


def form_client_request(transmit_timestamp: datetime.datetime = None) -> SNTPMessage:
    transmit_timestamp = transmit_timestamp or datetime.datetime.utcnow()
    return SNTPMessage(mode=Mode.CLIENT, transmit_ts=transmit_timestamp)


def get_time_from(hostname):
    sntp_reply = SNTPMessage.from_bytes(send_sntp_message_and_get_reply(form_client_request(), hostname))
    return sntp_reply.transmit_ts


if __name__ == '__main__':
    print(str(get_time_from("time.windows.com")))
