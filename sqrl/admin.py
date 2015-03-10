# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.contrib import admin

from .models import Identity, Nut


admin.site.register([Identity, Nut])
