# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.conf import settings
from django.db import models
from django.utils.encoding import python_2_unicode_compatible

from .crypto import generate_randomness
from .managers import SQRLNutManager


class SQRLIdentity(models.Model):
    """
    SQRL identity associated with a user.

    This model stores all necessary for SQRL to complete SQRL transactions
    and return any data to the client when necessary.

    The reason this is a standalone model vs lets say extending Django User model
    is because if added to the user model, each row for the user table is forced
    to allocate space to store SQRL information which might not be desired.
    By using a dedicated column, it allows to use SQRL only for users who use it.
    Also this makes Django-SQRL more modular so that it is easier integrated with
    existing projects.

    Attributes
    ----------
    public_key : str
        Base64 encoded public key of per-site user's SQRL public-private key pair.
        This key is used to verify users signature signing SQRL transaction
        including server generated random nut using users private key.
    server_unlock_key : str
        Base64 encoded server unlock key which is a public unlock key sent to client
        which client can use to generate urs (unlock request signature) signature which
        server can validate using vuk.
        More information can be found at https://www.grc.com/sqrl/idlock.htm.
    verify_unlock_key : str
        Base64 encoded verify unlock key which is a key stored by server which is used
        to validate urs (unlock request signature) signatures. This key is not sent to user.
        More information can be found at https://www.grc.com/sqrl/idlock.htm.
    is_enabled : bool
        Boolean indicating whether user can authenticate using SQRL.
    in_only_sqrl : bool
        Boolean indicating that only SQRL should be allowed to authenticate user.
        When enabled via flag in SQRL client requests, this should disable all other
        methods of authentication such as username/password.
    """
    user = models.OneToOneField(settings.AUTH_USER_MODEL, related_name='sqrl_identity')
    """Foreign key to Django's auth ``User`` object for whom this SQRL identity belongs to."""

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
        verbose_name = 'SQRL Identity'
        verbose_name_plural = 'SQRL Identities'


@python_2_unicode_compatible
class SQRLNut(models.Model):
    """
    Model for storing temporary state for SQRL transactions.

    This model by SQRL protocol is not strictly required.
    Here is the reasoning for it though:

    SQRL protocol requires couple of things:

    1. Each SQRL interaction must use random ``nonce`` or in SQRL terminology SQRL nut
    2. Strict enforcement that each nut can only be used at most once
    3. Each non-initiating SQRL request should return to the client some information
       about the initiating request such as whether IP address matches that of
       the IP where SQRL transaction was initiated.

    ``#3`` can easily be solved by encoding all necessary information in the nut value itself.
    On subsequent requests, server can simply decode all the information from the nut.
    That however will require nut value to grow pretty big. In addition this might also require
    encryption so that nut value by itself is not revealing. That in turn requires some
    rotating key management structure so that not all nuts are encrypted with same encryption key.
    All of the above is possible however is not very elegant, but again, is still possible.

    In addition, encrypting state in nut value does not hinder ``#1`` since some random bit
    can also be part of the nut so ``#1`` is not an issue.

    So far we dont need any state on the server. Each request can have its own nut value.

    The problem however is with ``#2`` requirement. The only way for the server to guarantee
    that nuts are never reused is to either keep a state of which nuts were used or keep state
    of all currently available nuts. Since keeping state of all used nuts will infinitely grow,
    probably the latter option is better. The default way of adding state in Django project
    would of been to add a model. But at that point, if you are creating a model anyway,
    might as well store everything in that model. As a benefit, it makes whole system
    simpler by not requiring any fancy approaches to encrypting nuts and maintaining
    rotated key encryption schedule of some sort.

    Attributes
    ----------
    nonce : str
        Base64 encoded value of a random nonce. This nonce is used to identify SQRL transaction.
        It is regenerated for each SQRL communication within a single SQRL transaction.
        Since this nonce is a one-time token, it allows for the server to prevent replay attacks.
        This columns is a primary key of the table.
    transaction_nonce : str
        Base64 encoded random nonce used to identify a full SQRL transaction from start to finish.
        Session key cannot be used since it is persistent across complete user visit which can
        include multiple tabs/windows. This transaction id is regenerated for each new tab which
        allows the client to identify when a particular SQRL transaction has completed
        hence redirect user to more appropriate page.
    session_key : str
        Session key of the session where SQRL transaction initiated which is used
        to associate client session to SQRL transaction. This is important because SQRL
        transaction can be completed on a different device which does not have access
        to original user session.
    is_transaction_complete : bool
        Boolean indicating whether SQRL transaction has completed. It is used by the
        :obj:`.views.SQRLStatusView` to return redirect URL to the user
        when transaction has completed.
    ip_address : str
        IP address of the user who initiated SQRL transaction. This is where
        initially SQRL link/qr code were generated.
    timestamp : datetime
        Last timestamp when nut was either created or modified. Used for puging purses
        to remove expired nuts.
    """
    nonce = models.CharField(
        max_length=43, unique=True, db_index=True, primary_key=True,
        help_text='Single-use random nonce used to identify SQRL transaction. '
                  'This nonce is regenerated for each SQRL communication within '
                  'a single SQRL transaction. Since this nonce is a one-time token, '
                  'it allows for the sviewerver to prevent replay attacks.'
    )
    transaction_nonce = models.CharField(
        max_length=43, unique=True, db_index=True,
        help_text='A random nonce used to identify a full SQRL transaction. '
                  'Session key cannot be used since it is persistent across '
                  'complete user visit which can include multiple tabs/windows. '
                  'This transaction id is regenerated for each new tab which '
                  'allows the client to identify when a particular SQRL transaction '
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

    objects = SQRLNutManager()

    class Meta(object):
        # Explicitly define db_table for clearer table name
        db_table = 'sqrl_nut'
        verbose_name = 'SQRL Nut'
        verbose_name_plural = 'SQRL Nuts'

    def __str__(self):
        return self.nonce

    def renew(self):
        """
        Renew instance of the nut.

        This is done by deleting the nut from the db since nonce is a primary key.
        Then nonce is regenerated and re-saved.
        """
        self.delete()
        self.nonce = generate_randomness()
        self.save()
