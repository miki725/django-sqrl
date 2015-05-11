# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.conf.urls import patterns, url

from .views import (
    SQRLAssociateIdentityView,
    SQRLAuthView,
    SQRLCompleteRegistrationView,
    SQRLLoginView,
    SQRLQRGeneratorView,
    SQRLStatusView,
)


urlpatterns = patterns(
    '',
    url(r'^login/$', SQRLLoginView.as_view(), name='login'),
    url(r'^qr/$', SQRLQRGeneratorView.as_view(), name='qr-image'),
    url(r'^auth/$', SQRLAuthView.as_view(), name='auth'),
    url(r'^status/(?P<transaction>[A-Za-z0-9_-]{43})/$', SQRLStatusView.as_view(), name='status'),
    url(r'^register/$', SQRLCompleteRegistrationView.as_view(), name='complete-registration'),
    url(r'^associate/$', SQRLAssociateIdentityView.as_view(), name='associate-identity'),
)
