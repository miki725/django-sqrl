# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.urls import re_path

from .views import (
    SQRLAuthView,
    SQRLCompleteRegistrationView,
    SQRLIdentityManagementView,
    SQRLLoginView,
    SQRLQRGeneratorView,
    SQRLStatusView,
)

app_name="sqrl"


urlpatterns = [
    re_path(r'^login/$', SQRLLoginView.as_view(), name='login'),
    re_path(r'^qr/$', SQRLQRGeneratorView.as_view(), name='qr-image'),
    re_path(r'^auth/$', SQRLAuthView.as_view(), name='auth'),
    re_path(r'^status/(?P<transaction>[A-Za-z0-9_-]{43})/$', SQRLStatusView.as_view(), name='status'),
    re_path(r'^register/$', SQRLCompleteRegistrationView.as_view(), name='complete-registration'),
    re_path(r'^manage/$', SQRLIdentityManagementView.as_view(), name='manage'),
]
