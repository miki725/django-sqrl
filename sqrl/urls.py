# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.conf.urls import patterns, url

from .views import (
    SQRLAuthView,
    SQRLCheckView,
    SQRLLoginView,
    SQRLQRGeneratorView,
)


urlpatterns = patterns(
    '',
    url(r'login/$',
        SQRLLoginView.as_view(),
        name='login'),
    url(r'^qr/$',
        SQRLQRGeneratorView.as_view(),
        name='qr-image'),
    url(r'^check/$',
        SQRLCheckView.as_view(),
        name='auth'),
    url(r'^auth/$',
        SQRLAuthView.as_view(),
        name='auth'),
)
