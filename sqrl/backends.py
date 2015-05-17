# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.contrib.auth.backends import ModelBackend

from .models import SQRLIdentity


class SQRLModelBackend(ModelBackend):
    """
    Custom SQRL Authentication backend which honors ``only_sqrl`` when enabled.

    SQRL, by its spec, allows users to send ``only_sqrl`` flag to the server
    which indicates to the server that it should only use SQRL
    for authentication and disable all other methods of authentication.
    This custom authentication backend implements that requirement.
    It honors the ``only_sqrl`` spec and does not allow to authenticate
    a user when following conditions are all ``True``:

    * user successfully validated credentials using traditional auth method
    * user has SQRL identity associated with their account
    * :attr:`.models.SQRLIdentity.in_only_sqrl` is ``True``
    """

    def authenticate(self, *args, **kwargs):
        """
        Same as Django's ``ModelBackend.authenticate`` except
        this method honors ``only_sqrl`` SQRL spec.
        """
        user = super(SQRLModelBackend, self).authenticate(*args, **kwargs)

        if user is None:
            return

        try:
            sqrl_identity = user.sqrl_identity
        except SQRLIdentity.DoesNotExist:
            return user
        else:
            if sqrl_identity.is_only_sqrl and sqrl_identity.is_enabled:
                return

        return user
