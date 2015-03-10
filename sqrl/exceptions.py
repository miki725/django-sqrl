# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals


def make_tif_property(val):
    return lambda self: bool(self & val)


class TIF(int):
    ID_MATCH = 0x1
    PREVIOUS_ID_MATCH = 0x2
    IP_MATCH = 0x4
    SQRL_DISABLED = 0x8
    NOT_SUPPORTED = 0x10
    TRANSIENT_FAILURE = 0x20
    COMMAND_FAILED = 0x40
    CLIENT_FAILURE = 0x80

    is_id_match = property(make_tif_property(ID_MATCH))
    is_previous_id_match = property(make_tif_property(PREVIOUS_ID_MATCH))
    is_ip_match = property(make_tif_property(IP_MATCH))
    is_sqrl_disabled = property(make_tif_property(SQRL_DISABLED))
    is_transient_failure = property(make_tif_property(TRANSIENT_FAILURE))
    is_command_failed = property(make_tif_property(COMMAND_FAILED))
    is_client_failure = property(make_tif_property(CLIENT_FAILURE))
    is_not_supported = property(make_tif_property(NOT_SUPPORTED))

    def as_hex_string(self):
        return '{:x}'.format(self)

    def breakdown(self):
        return {
            k.lower(): bool(self & v)
            for k, v in vars(self.__class__).items()
            if not k.startswith('_') and k.isupper()
        }

    def update(self, other):
        return type(self)(self | other)


class TIFException(Exception):
    def __init__(self, tif):
        self.tif = TIF(tif)
