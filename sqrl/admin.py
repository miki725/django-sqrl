# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.contrib import admin

from .models import SQRLIdentity, SQRLNut


class SQRLIdentityAdmin(admin.ModelAdmin):
    model = SQRLIdentity
    list_display = (
        'user',
        'is_enabled',
        'is_only_sqrl',
    )
    raw_id_fields = (
        'user',
    )


class SQRLNutAdmin(admin.ModelAdmin):
    model = SQRLNut
    list_display = (
        'nonce',
        'is_transaction_complete',
        'ip_address',
    )


admin.site.register(SQRLNut, SQRLNutAdmin)
admin.site.register(SQRLIdentity, SQRLIdentityAdmin)
