# !/usr/bin/env python3
import datetime as dt
from enum import IntEnum, unique
from typing import Union

SNTP_MESSAGE_LENGTHS = [48,48+4,48+16,48+16+4]

MIN_DATETIME = dt.datetime(1968, 1, 1)

INITIAL_TIME_0_BIT_SET = dt.datetime(year=1900, month=1, day=1)
INITIAL_TIME_0_BIT_UNSET = dt.datetime(year=2036, month=2, day=7,
                                       hour=6, minute=28, second=16)


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


class SNTPMessage:
    def __init__(self,
                 li=LI.NO_WARNING,
                 version: int = 4,
                 mode: Mode = Mode.PRIVATE_RESERVED,
                 stratum: int = 255,
                 poll: int = 0,
                 precision: int = -20,
                 root_delay: float = 0,
                 root_dispersion: float = 0,
                 ref_id: bytes = b"\x00\x00\x00\x00",
                 ref_ts: dt.datetime = None,
                 orig_ts: dt.datetime = None,
                 rcv_ts: dt.datetime = None,
                 transmit_ts: dt.datetime = None
                 ):
        self.li = li
        self.version = version
        self.mode = mode
        self.stratum = stratum
        self.poll = poll
        self.precision = precision
        self.root_delay = root_delay
        self.root_dispersion = root_dispersion
        self.ref_id = ref_id
        self.ref_ts = ref_ts
        self.orig_ts = orig_ts
        self.rcv_ts = rcv_ts
        self.transmit_ts = transmit_ts

    @staticmethod
    def from_bytes(bytes_: bytes, expected_modes: list = list()):
        message_length = len(bytes_)
        if message_length not in SNTP_MESSAGE_LENGTHS:
            raise ValueError(
                "Invalid message length: expected: {}, got: {:d}".format(
                    str(SNTP_MESSAGE_LENGTHS), message_length))

        leap_indicator = LI((bytes_[0] & 0b11000000) >> 6)
        version = (bytes_[0] & 0b00111000) >> 3

        mode = Mode(bytes_[0] & 0b00000111)
        if mode not in expected_modes:
            raise ValueError(
                "Got an unexpected mode; expected: {}, got: {}".format(
                    str(expected_modes), str(mode)))

        stratum = bytes_[1]
        poll = bytes_[2]
        precision = bytes_[3] if bytes_[3] <= 127 else -(256 - bytes_[3])
        root_delay = _bytes_signed_fixed_to_float(bytes_[4:4 + 4], 16,
                                                  signed=True)
        root_dispersion = _bytes_signed_fixed_to_float(
            bytes_[8:8 + 4], 16, signed=False)
        reference_id = bytes_[12:12 + 4]
        reference_ts = _datetime_from_bytes(bytes_[16:16 + 8])
        origin_ts = _datetime_from_bytes(bytes_[24:24 + 8])
        receive_ts = _datetime_from_bytes(bytes_[32:32 + 8])
        transmit_ts = _datetime_from_bytes(bytes_[40:40 + 8])
        return SNTPMessage(leap_indicator, version, mode, stratum,
                           poll, precision,
                           root_delay, root_dispersion, reference_id,
                           reference_ts, origin_ts, receive_ts, transmit_ts)

    def to_bytes(self):
        message = bytearray(48)  # 68)
        message[0] = ((self.li & 0b11) << 6) | \
                     ((self.version & 0b111) << 3) | \
                     (self.mode & 0b111)
        message[1] = self.stratum & 0xff
        message[2] = self.poll & 0xff
        message[3] = self.precision.to_bytes(1, "big", signed=True)[0]
        message[4:4 + 4] = _float_to_signed_fixed_bytes(
            self.root_delay, 4, 16, signed=True)
        message[8:8 + 4] = _float_to_signed_fixed_bytes(
            self.root_dispersion, 4, 16, signed=False)
        message[12:12 + 4] = self.ref_id
        message[16:16 + 8] = datetime_to_bytes(self.ref_ts)
        message[24:24 + 8] = datetime_to_bytes(self.orig_ts)
        message[32:32 + 8] = datetime_to_bytes(self.rcv_ts)
        message[40:40 + 8] = datetime_to_bytes(self.transmit_ts)

        return message


def _bytes_signed_fixed_to_float(b: Union[bytes, bytearray],
                                 fraction_start_bit: int,
                                 signed: bool) -> float:
    length_bites = 8 * len(b)

    result = 0

    for i in range(1 if signed else 0, fraction_start_bit):
        result = result * 2 + (1 if (b[i // 8] & (1 << (7 - (i % 8)))) else 0)

    addition = 0.5
    for i in range(fraction_start_bit, length_bites):
        if b[i // 8] & (1 << (7 - (i % 8))):
            result += addition
        addition /= 2

    negative = signed and bool(b[0] & 0b10000000)

    if negative:
        result *= -1

    return result


def _float_to_signed_fixed_bytes(f: float,
                                 length: int,
                                 fraction_start_bit: int,
                                 signed: bool
                                 ) -> bytes:
    if not signed and f < 0:
        raise ValueError("Can't encode negative float as unsigned")
    length_bits = 8 * length
    if (
            fraction_start_bit > length_bits or
            fraction_start_bit < 0 or
            signed and fraction_start_bit == 0
    ):
        raise ValueError("Fraction start bit is out of range")

    fraction_part_length_bits = length_bits - fraction_start_bit
    int_part_length_bits = length_bits - (1 if signed else 0) - \
                           fraction_part_length_bits

    int_part_trimmed_abs_float = abs(f) & (
            (2 << (int_part_length_bits - 1)) - 1)

    shifted = int_part_trimmed_abs_float * (2 ** fraction_part_length_bits)

    int_repr = int(shifted)

    result_bytes = int_repr.to_bytes(length, byteorder='big', signed=False)
    result_bytes = bytearray(result_bytes)

    if signed and f < 0:
        result_bytes[0] = result_bytes[0] | 0b10000000

    return bytes(result_bytes)


def _datetime_from_bytes(bytes_: bytes) -> dt.datetime:
    seconds = int.from_bytes(bytes_[0:4], byteorder="big", signed=False)
    sec_fractions = int.from_bytes(bytes_[4:8], byteorder="big",
                                   signed=False) / (2 ** 32)
    milliseconds = int(sec_fractions * 1000)
    microseconds = (sec_fractions * 1000000) % 1000

    initial_time = INITIAL_TIME_0_BIT_SET if bytes_[0] & 0b10000000 \
        else INITIAL_TIME_0_BIT_UNSET

    return initial_time + dt.timedelta(
        seconds=seconds,
        milliseconds=milliseconds,
        microseconds=microseconds)


def datetime_to_bytes(datetime_: dt.datetime) -> bytes:
    if datetime_ is None:
        return b"\x00" * 8

    if datetime_ < MIN_DATETIME:
        raise ValueError("Cannot encode dates sooner than 1 January 1968")

    use_2036_as_start = datetime_ >= INITIAL_TIME_0_BIT_UNSET

    initial_time = INITIAL_TIME_0_BIT_UNSET if use_2036_as_start \
        else INITIAL_TIME_0_BIT_SET

    delta = datetime_ - initial_time
    delta_seconds = delta.total_seconds()

    seconds_int = int(delta_seconds)
    if use_2036_as_start and seconds_int >= 0x80000000:
        raise ValueError("Cannot encode dates that late")

    seconds_fraction = int((delta_seconds - seconds_int) * (2 ** 32))

    return (seconds_int.to_bytes(4, byteorder='big', signed=False) +
            seconds_fraction.to_bytes(4, byteorder='big', signed=False))
