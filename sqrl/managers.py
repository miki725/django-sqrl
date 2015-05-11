# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.db import models


class NutManager(models.Manager):
    def replace_or_create(self, session_key, **kwargs):
        self.get_queryset().filter(session_key=session_key).delete()
        return self.create(session_key=session_key, **kwargs)
