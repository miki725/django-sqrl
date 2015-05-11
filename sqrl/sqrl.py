# -*- coding: utf-8 -*-
from __future__ import division, print_function, unicode_literals

from django.core.urlresolvers import reverse
from django.http import QueryDict

from .crypto import generate_randomness
from .models import SQRLNut
from .utils import get_user_ip


class SQRLInitialization(object):
    def __init__(self, request, nut=None):
        self.request = request
        if nut is not None:
            self.nut = nut

    def get_session_key(self):
        session_key = self.request.session.session_key

        if session_key is None:
            self.request.session.create()
            session_key = self.request.session.session_key

        return session_key

    @property
    def nut(self):
        if hasattr(self, '_nut'):
            return self._nut

        self._nut = SQRLNut.objects.replace_or_create(
            **self.generate_nut_kwargs()
        )

        return self._nut

    @nut.setter
    def nut(self, value):
        self._nut = value

    def generate_nut_kwargs(self):
        randomness = generate_randomness(64)
        l = len(randomness) // 2

        return {
            'session_key': self.get_session_key(),
            'nonce': randomness[:l],
            'transaction_nonce': randomness[l:],
            'is_transaction_complete': False,
            'ip_address': get_user_ip(self.request),
        }

    def get_sqrl_url(self):
        return reverse('sqrl:auth')

    def get_sqrl_url_params(self):
        qd = QueryDict('', mutable=True)
        qd.update({
            'nut': self.nut.nonce,
        })
        return qd.urlencode()

    @property
    def url(self):
        return (
            '{url}?{params}'
            ''.format(url=self.get_sqrl_url(),
                      params=self.get_sqrl_url_params())
        )

    @property
    def sqrl_url(self):
        return (
            '{scheme}://{host}{url}'
            ''.format(scheme='sqrl' if self.request.is_secure() else 'qrl',
                      host=self.request.get_host(),
                      url=self.url)
        )
