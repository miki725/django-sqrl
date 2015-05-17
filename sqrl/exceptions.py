# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals


def _make_tif_property(val):
    """
    Helper function for generating property methods for :obj:`.TIF`
    which will boolean whether a particular SQRL ``TIF`` bit is ``True``
    in the ``TIF`` value.

    Parameters
    ----------
    val : int
        Value with particular ``True`` bit which will be tested
        within the generated property.

    Returns
    -------
    function
        Function which can be made into a property
    """

    def is_bit_present(self):
        """
        Property which returns boolean whether ``{hex}`` or ``{bits}``
        bit is present in the TIF value.
        """
        return bool(self & val)

    is_bit_present.__doc__ = is_bit_present.__doc__.format(
        hex=hex(val),
        bits=bin(val),
    )

    return is_bit_present


class TIF(int):
    """
    SQRL ``TIF`` ``int`` subclass which can represent SQRL ``TIF`` flags.

    Example
    -------

    ::

        >>> tif = TIF(TIF.IP_MATCH | TIF.TRANSIENT_FAILURE | TIF.COMMAND_FAILED)
        >>> tif.is_ip_match
        True
        >>> tif.is_id_match
        False
        >>> tif.is_transient_failure
        True
        >>> tif
        100
        >>> tif.as_hex_string()
        '64'
        >>> tif.breakdown() == {
        ...     'id_match': False,
        ...     'previous_id_match': False,
        ...     'ip_match': True,
        ...     'sqrl_disabled': False,
        ...     'not_supported': False,
        ...     'transient_failure': True,
        ...     'command_failed': True,
        ...     'client_failure': False,
        ... }
        True
    """
    ID_MATCH = 0x1
    """SQRL ID was found in DB"""
    PREVIOUS_ID_MATCH = 0x2
    """Previous SQRL ID was found in DB"""
    IP_MATCH = 0x4
    """SQRL client is used from same IP as where transaction started"""
    SQRL_DISABLED = 0x8
    """SQRL auth is disabled for the found SQRL identity as per users request"""
    NOT_SUPPORTED = 0x10
    """SQRL client requested SQRl operation which is not supported"""
    TRANSIENT_FAILURE = 0x20
    """SQRL command failed transiently. Most likely restarting SQRL transaction should fix this"""
    COMMAND_FAILED = 0x40
    """SQRL command failed for any reason"""
    CLIENT_FAILURE = 0x80
    """SQRL command failed because SQRL client sent invalid data"""

    is_id_match = property(_make_tif_property(ID_MATCH))
    is_previous_id_match = property(_make_tif_property(PREVIOUS_ID_MATCH))
    is_ip_match = property(_make_tif_property(IP_MATCH))
    is_sqrl_disabled = property(_make_tif_property(SQRL_DISABLED))
    is_transient_failure = property(_make_tif_property(TRANSIENT_FAILURE))
    is_command_failed = property(_make_tif_property(COMMAND_FAILED))
    is_client_failure = property(_make_tif_property(CLIENT_FAILURE))
    is_not_supported = property(_make_tif_property(NOT_SUPPORTED))

    def as_hex_string(self):
        """
        Return TIF value as hex string
        """
        return '{:x}'.format(self)

    def breakdown(self):
        """
        Returns a full breakdown of the TIF value.

        Returns
        -------
        dict
            Keys are the SQRL TIF property and values are booleans.
        """
        return {
            k.lower(): bool(self & v)
            for k, v in vars(self.__class__).items()
            if not k.startswith('_') and k.isupper()
        }

    def update(self, other):
        """
        Return updated TIF which will contain both bits already set
        in the ``self`` value as well as the ``other value.

        Parameters
        ----------
        other : int
            Other ``TIF`` value which be merged with ``self`` bits

        Returns
        -------
        TIF
            New :obj:`.TIF` value which has merged bits.
        """
        return type(self)(self | other)


class TIFException(Exception):
    """
    Custom Exception which can be used in the views to raise
    specific :obj:`.TIF` bits and immediately return appropriate response
    to the user.
    """

    def __init__(self, tif):
        self.tif = TIF(tif)
