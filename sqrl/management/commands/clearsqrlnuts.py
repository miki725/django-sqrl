# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils.timezone import now

from sqrl.models import Nut


class Command(BaseCommand):
    help = ('Clears expired SQRL nuts. '
            'This command should be used as a cron job. '
            'The recommended execution frequency is 5 minutes '
            'which will result in longest nut lifespan of 10 minutes.')

    def handle(self, *args, **options):
        ttl = getattr(settings, 'SQRL', {}).get('TTL', 60 * 5)  # 5 minutes
        delete_before = now() + timedelta(seconds=-ttl)
        Nut.objects.filter(created__lt=delete_before).delete()
