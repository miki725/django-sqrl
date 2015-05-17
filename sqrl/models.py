# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.conf import settings
from django.db import models
from django.utils.encoding import python_2_unicode_compatible

from .crypto import generate_randomness
from .managers import NutManager


class SQRLIdentity(models.Model):
    """
    Attributes
    ----------
    in_only_sqrl : bool
        Boolean indicating that only SQRL should be allowed to authenticate user
    """
    user = models.OneToOneField(settings.AUTH_USER_MODEL, related_name='sqrl_identity')

    public_key = models.CharField(
        max_length=43, db_index=True, unique=True,
        help_text='Public key of per-site users public-private key pair. '
                  'This key is used to verify users signature signing SQRL transaction '
                  'including server generated random nut using users private key.'
    )
    server_unlock_key = models.CharField(
        max_length=43, blank=True,
        help_text='This is public unlock key sent to client which client can use to '
                  'generate urs (unlock request signature) signature which server can validate '
                  'using vuk.'
    )
    verify_unlock_key = models.CharField(
        max_length=43, blank=True,
        help_text='This is a key stored by server which is used to validate '
                  'urs (unlock request signature) signatures. This key is not sent to user.'
    )
    is_enabled = models.BooleanField(
        default=True,
        help_text='Boolean indicating whether user can authenticate using SQRL.'
    )
    is_only_sqrl = models.BooleanField(
        default=False,
        help_text='Boolean indicating that only SQRL should be allowed to authenticate user. '
                  'When enabled via flag in SQRL client requests, this should disable all other '
                  'methods of authentication such as username/password.'
    )

    class Meta(object):
        # Redefine db_table so that table name is not funny
        # like sqrl_sqrlidentity.
        # One way to solve that is to simply name the model
        # Identity however that is generic enough which might cause
        # name conflicts so its easier to rename the model
        # and manually overwrite the table name
        db_table = 'sqrl_identity'


@python_2_unicode_compatible
class SQRLNut(models.Model):
    """
    Attributes
    ----------
    session_key : str
        Session key
    """
    nonce = models.CharField(
        max_length=43, unique=True, db_index=True, primary_key=True,
        help_text='Single-use random nonce used to identify SQRL transaction. '
                  'This nonce is regenerated for each SQRL communication within '
                  'a single SQRL transaction. Since this nonce is a one-time token, '
                  'it allows for the server to prevent replay attacks.'
    )
    transaction_nonce = models.CharField(
        max_length=43, unique=True, db_index=True,
        help_text='A random nonce used to identify a full SQRL transaction. '
                  'Session key cannot be used since it is persistent across '
                  'complete user visit which can include multiple tabs/windows. '
                  'This transaction id is regenerated for each new tab which '
                  'allows the client to identity when a particular SQRL transaction '
                  'has completed hence redirect user to more appropriate page.'
    )

    session_key = models.CharField(
        max_length=32, unique=True, db_index=True,
        help_text='User regular session key. This is used to associate client session '
                  'to a SQRL transaction since transaction can be completed on a different '
                  'device which does not have access to original user session.'
    )

    is_transaction_complete = models.BooleanField(
        default=False,
        help_text='Indicator whether transaction is complete. '
                  'Can we used by UI to automatically redirect to appropriate page '
                  'once SQRL transaction is complete.',
    )
    ip_address = models.GenericIPAddressField(
        help_text='Originating IP address of client who initiated SQRL transaction. '
                  'Used to set appropriate TIF response code.',
    )
    timestamp = models.DateTimeField(
        auto_now=True,
        help_text='Last timestamp when nut was either created or modified. '
                  'Used for purging purposes.',
    )

    objects = NutManager()

    class Meta(object):
        # Explicitly define db_table for clearer table name
        db_table = 'sqrl_nut'

    def __str__(self):
        return self.nonce

    def renew(self):
        self.delete()
        self.nonce = generate_randomness()
        self.save()
