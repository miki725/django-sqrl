# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.contrib import admin

from .models import SQRLIdentity, SQRLNut


admin.site.register([SQRLIdentity, SQRLNut])
