# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.conf import settings
from django.contrib.auth.models import AbstractUser, UserManager as _UserManager
from django.db import models

from .utils import generate_nonce


class IdentityManager(_UserManager):
    pass


class SQRLIdentity(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, related_name='sqrl_identity')

    public_key = models.CharField(max_length=43, db_index=True, unique=True)
    verify_unlock_key = models.CharField(max_length=43, blank=True)
    server_unlock_key = models.CharField(max_length=43, blank=True)
    is_enabled = models.BooleanField(default=True)
    is_only_sqrl = models.BooleanField(default=False)

    objects = IdentityManager()

    class Meta(object):
        # Redefine db_table so that table name is not funny
        # like sqrl_sqrlidentity.
        # One way to solve that is to simply name the model
        # Identity however that is generic enough which might cause
        # name conflicts so its easier to rename the model
        # and manually overwrite the table name
        db_table = 'sqrl_identity'


class NutManager(models.Manager):
    def replace_or_create(self, session_key, **kwargs):
        self.get_queryset().filter(session_key=session_key).delete()
        return self.create(session_key=session_key, **kwargs)


class Nut(models.Model):
    nonce = models.CharField(max_length=43, unique=True, db_index=True, primary_key=True)
    session_key = models.CharField(max_length=32, unique=True, db_index=True)
    ip_address = models.GenericIPAddressField()
    created = models.DateTimeField(auto_now_add=True)

    objects = NutManager()

    def renew_nonce(self):
        self.nonce = generate_nonce()
        self.save()
