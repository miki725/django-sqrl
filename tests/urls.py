# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.conf.urls import include, patterns, url
from django.contrib import admin
from django.contrib.auth.urls import urlpatterns as auth_urlpatterns
from django.contrib.auth.views import logout

from sqrl.urls import urlpatterns as sqrl_urlpatterns


urlpatterns = patterns(
    '',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^sqrl/', include(sqrl_urlpatterns, namespace='sqrl')),
    url(r'^logout/', logout, {'next_page': 'sqrl:login'}, name='logout'),
    url(r'^', include(auth_urlpatterns)),
)
