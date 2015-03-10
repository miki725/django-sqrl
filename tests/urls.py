# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
from django.conf.urls import patterns, url, include
from sqrl.urls import urlpatterns as sqrl_urlpatterns


urlpatterns = patterns(
    '',
    url(r'^sqrl/', include(sqrl_urlpatterns, namespace='sqrl'))
)
