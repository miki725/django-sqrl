# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.contrib.auth.backends import ModelBackend

from .models import SQRLIdentity


class SQRLModelBackend(ModelBackend):
    def authenticate(self, *args, **kwargs):
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
