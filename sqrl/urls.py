# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.conf.urls import patterns, url

from .views import (
    SQRLAuthView,
    SQRLCompleteRegistrationView,
    SQRLLoginView,
    SQRLQRGeneratorView,
    SQRLStatusView,
)


urlpatterns = patterns(
    '',
    url(r'login/$', SQRLLoginView.as_view(), name='login'),
    url(r'^qr/$', SQRLQRGeneratorView.as_view(), name='qr-image'),
    url(r'^auth/$', SQRLAuthView.as_view(), name='auth'),
    url(r'^status/$', SQRLStatusView.as_view(), name='status'),
    url(r'^register/$', SQRLCompleteRegistrationView.as_view(), name='complete-registration'),
)
