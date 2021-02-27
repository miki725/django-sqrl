# -*- coding: utf-8 -*-
from __future__ import division, print_function, unicode_literals

from django.urls import reverse
from django.http import QueryDict

from .crypto import generate_randomness
from .models import SQRLNut
from .utils import get_user_ip


class SQRLInitialization(object):
    """
    SQRL class for initializing SQRL transaction.

    This class is mainly responsible for initially creating and storing
    :obj:`.models.SQRLNut`. Also this class has helper properties
    for getting SQRL urls.

    Parameters
    ----------
    request : HttpRequest
        Django standard request object
    nut : SQRLNut, optional
        SQRLNut for which to do SQRL initialization
    """

    def __init__(self, request, nut=None):
        self.request = request
        if nut is not None:
            self.nut = nut

    def get_or_create_session_key(self):
        """
        Get or create the session key from the request object.

        When not present yet, this initializes the session for the user.
        As a result, the request then returns session cookie to the user
        via session middleware.
        """
        session_key = self.request.session.session_key

        if session_key is None:
            self.request.session.create()
            session_key = self.request.session.session_key

        return session_key

    @property
    def nut(self):
        """
        Cached property for getting :obj:`.models.SQRLNut`.

        When accessed for the first time, this property either replaces or creates
        new :obj:`.models.SQRLNut` by using :meth:`.managers.SQRLNutManager.replace_or_create`.
        All the data for the creation of the nut is created by using :meth:`.generate_nut_kwargs`.
        """
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
        """
        Generate kwargs which can be used to create new :obj:`.models.SQRLNut`.

        Returns
        -------
        dict
            All required kwargs to instantiate and create :obj:`.models.SQRLNut`.
        """
        randomness = generate_randomness(64)
        l = len(randomness) // 2

        return {
            'session_key': self.get_or_create_session_key(),
            'nonce': randomness[:l],
            'transaction_nonce': randomness[l:],
            'is_transaction_complete': False,
            'ip_address': get_user_ip(self.request),
        }

    def get_sqrl_url(self):
        """
        Get the server URL of where SQRL client will make first request.

        This method should be customized when a custom namespace should be used
        by the SQRL client when generating on the fly per-site public-private keypair.
        For example this can be used when a web site is a SAAS in which different
        "sub-sites" are determined tenant within a URL path - ``mysaas.com/<tenant>``.
        In that case the returned SQRL auth url should be something like -
        ``mysaas.com/mytenant:sqrl/auth/?nut=<nut value>``.
        By using ``:`` within the path will let SQRL client know that up until
        that point full domain name should be used to generate public-private keypair.
        """
        return reverse('sqrl:auth')

    def get_sqrl_url_params(self):
        """
        Get SQRL url params to be added as querystring params in the SQRL url.

        By default this only adds ``nut=<nut>``.

        Returns
        -------
        str
            URLEncoded querystring params
        """
        qd = QueryDict('', mutable=True)
        qd.update({
            'nut': self.nut.nonce,
        })
        return qd.urlencode()

    @property
    def url(self):
        """
        Property for getting only server-side SQRL auth view URL.

        This does not include the full domain within the URL.
        The URL is always relative to the current domain of the site.
        """
        return (
            '{url}?{params}'
            ''.format(url=self.get_sqrl_url(),
                      params=self.get_sqrl_url_params())
        )

    @property
    def sqrl_url(self):
        """
        Property for getting full SQRL auth view URL including SQRL scheme and full domain with port.
        """
        return (
            '{scheme}://{host}{url}'
            ''.format(scheme='sqrl' if self.request.is_secure() else 'sqrl',
                      host=self.request.get_host(),
                      url=self.url)
        )
