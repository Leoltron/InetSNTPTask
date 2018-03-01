# !/usr/bin/env python3
import socket
from enum import IntEnum, unique
import datetime as dt


@unique
class LI(IntEnum):
    NO_WARNING = 0
    SIXTY_ONE_IN_LAST_MINUTE = 1
    FIFTY_NINE_IN_LAST_MINUTE = 2
    ALARM = 3


@unique
class Mode(IntEnum):
    RESERVED = 0
    SYMMETRIC_ACTIVE = 1
    SYMMETRIC_PASSIVE = 2
    CLIENT = 3
    SERVER = 4
    BROADCAST = 5
    NTP_CONTROL_RESERVED = 6
    PRIVATE_RESERVED = 7


def send_sntp_message_and_get_reply(message, hostname, tries=4, timeout=2):
    return send_udp_message_and_get_reply(message, 123, hostname, tries,
                                          timeout)


def send_udp_message_and_get_reply(message, port, hostname, tries=4,
                                   timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try_ = 0
    while True:
        sock.sendto(message, (hostname, port))
        try:
            reply = sock.recv(1024)
            return reply
        except socket.timeout:
            try_ += 1
            if try_ > tries > 0:
                raise TimeoutError("Out of tries")
            print("Timeout has reached, trying again")


def form_sntp_message(
        li=LI.NO_WARNING,
        version=4,
        mode=0,
        stratum=255,
        poll=0,
        precision=-20,
        root_delay=0,
        root_dispersion=0,
        ref_id=b"\x00\x00\x00\x00",
        ref_ts: dt.datetime = dt.datetime(1900, 1, 1),
        orig_ts: dt.datetime = dt.datetime(1900, 1, 1),
        rcv_ts: dt.datetime = dt.datetime(1900, 1, 1),
        transmit_ts: dt.datetime = dt.datetime(1900, 1, 1)
        # key_id=None,
        # message_digset=None
) -> bytes:
    message = bytearray(48)  # 68)
    message[0] = ((li & 0b11) << 6) | \
                 ((version & 0b111) << 3) | \
                 (mode & 0b111)
    message[1] = stratum & 0xff
    message[2] = poll & 0xff
    message[3] = precision.to_bytes(1, "big", signed=True)[0]
    message[4:4 + 4] = float_to_signed_fixed_bytes(
        root_delay, 4, 16, signed=True)
    message[8:8 + 4] = float_to_signed_fixed_bytes(
        root_dispersion, 4, 16, signed=False)
    message[12:12 + 4] = ref_id
    message[16:16 + 8] = datetime_to_bytes(ref_ts)
    message[24:24 + 8] = datetime_to_bytes(orig_ts)
    message[32:32 + 8] = datetime_to_bytes(rcv_ts)
    message[40:40 + 8] = datetime_to_bytes(transmit_ts)

    return message


def parse_sntp_message(bytes_: bytes):
    leap_indicator = (bytes_[0] & 0b11000000) >> 6
    version = (bytes_[0] & 0b00111000) >> 3
    mode = (bytes_[0] & 0b00000111)
    stratum = bytes_[1]
    poll = bytes_[2]
    precision = bytes_[3] if bytes_[3] <= 127 else -(256 - bytes_[3])
    root_delay = bytes_signed_fixed_to_float(
        bytes_[4:4 + 4], 16, signed=True)
    root_dispersion = bytes_signed_fixed_to_float(
        bytes_[8:8 + 4], 16, signed=False)
    ref_id = bytes_[12:12 + 4]
    ref_ts = datetime_from_bytes(bytes_[16:16 + 8])
    orig_ts = datetime_from_bytes(bytes_[24:24 + 8])
    rcv_ts = datetime_from_bytes(bytes_[32:32 + 8])
    transmit_ts = datetime_from_bytes(bytes_[40:40 + 8])
    return leap_indicator, version, mode, stratum, poll, precision, \
           root_delay, root_dispersion, ref_id, ref_ts, orig_ts, rcv_ts, \
           transmit_ts


def bytes_signed_fixed_to_float(b, fraction_start_bit, signed) -> float:
    length_bites = 8 * len(b)
    if signed:
        negative = bool(b[0] & 0b10000000)
    result = 0
    for i in range(1 if signed else 0, fraction_start_bit):
        result = result * 2 + (1 if (b[i // 8] & (1 << (7 - (i % 8)))) else 0)
    addition = 0.5
    for i in range(fraction_start_bit, length_bites):
        if b[i // 8] & (1 << (7 - (i % 8))):
            result += addition
        addition /= 2
    if signed and negative:
        result *= -1
    return result


def float_to_signed_fixed_bytes(f, length, fraction_start_bit,
                                signed) -> bytes:
    length_bites = 8 * length
    fraction_part_length_bites = length_bites - fraction_start_bit
    int_part_length_bites = length_bites - (1 if signed else 0) - \
                            fraction_part_length_bites
    bytes_ = bytearray(length)
    if f < 0:
        bytes_[0] = bytes_[0] | 0b10000000

    int_part = int(f)
    for i in range(int_part_length_bites - 1, 0 if signed else -1, -1):
        if int_part % 2 == 1:
            byte_number = i // 8
            bytes_[byte_number] = bytes_[byte_number] | (1 << (7 - (i % 8)))
        int_part = int_part // 2

    float_part = f - int(f)
    for i in range(fraction_start_bit, length_bites):
        float_part *= 2
        if float_part >= 1:
            byte_number = i // 8
            bytes_[byte_number] = bytes_[byte_number] | (1 << (7 - (i % 8)))
            float_part -= 1
    return bytes(bytes_)


initial_time = dt.datetime(year=1900, month=1, day=1)


def datetime_from_bytes(bytes_: bytes) -> dt.datetime:
    seconds = int.from_bytes(bytes_[0:4], byteorder="big", signed=False)
    sec_fractions = int.from_bytes(bytes_[4:8], byteorder="big",
                                   signed=False) / (2 ** 32)
    milliseconds = int(sec_fractions * 1000)
    microseconds = (sec_fractions * 1000000) % 1000
    return initial_time + dt.timedelta(
        seconds=seconds,
        milliseconds=milliseconds,
        microseconds=microseconds)


def datetime_to_bytes(datetime_: dt.datetime) -> bytes:
    delta = datetime_ - initial_time
    delta_seconds = delta.total_seconds()

    seconds_int = int(delta_seconds)
    seconds_fraction = int((delta_seconds - seconds_int) * (2 ** 32))

    return seconds_int.to_bytes(4, byteorder='big', signed=False) + \
           seconds_fraction.to_bytes(4, byteorder='big', signed=False)


if __name__ == '__main__':
    datetime_to_bytes(dt.datetime(2000, 1, 1, microsecond=55))
