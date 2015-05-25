# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import json
import unittest

import mock
from django import test
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import serializers
from django.core.urlresolvers import reverse
from django.http import Http404, QueryDict
from django.views.generic import FormView

from ..models import SQRLIdentity, SQRLNut
from ..views import (
    SQRL_IDENTITY_SESSION_KEY,
    SQRLCompleteRegistrationView,
    SQRLQRGeneratorView,
    SQRLStatusView,
)


TESTING_MODULE = 'sqrl.views'


class TestSQRLQRGeneratorView(unittest.TestCase):
    def setUp(self):
        super(TestSQRLQRGeneratorView, self).setUp()
        self.view = SQRLQRGeneratorView()
        self.view.request = mock.MagicMock(GET=QueryDict('url=sqrl://example.com/'))

    def test_get(self):
        response = self.view.get(self.view.request)

        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.content), 0)
        self.assertEqual(response['content-type'], 'image/png')

    def test_get_form_kwargs(self):
        actual = self.view.get_form_kwargs()

        self.assertDictEqual(actual, {
            'data': self.view.request.GET,
            'initial': {},
            'prefix': None,
        })

    def test_form_invalid(self):
        response = self.view.form_invalid(self.view.get_form(self.view.get_form_class()))

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response['content-type'], 'application/json')

    def test_form_valid(self):
        form = self.view.get_form(self.view.get_form_class())
        form.is_valid()

        response = self.view.form_valid(form)

        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.content), 0)
        self.assertEqual(response['content-type'], 'image/png')


class TestSQRLStatusView(test.TestCase):
    def setUp(self):
        super(TestSQRLStatusView, self).setUp()
        self.view = SQRLStatusView()
        self.view.request = mock.MagicMock(GET={})
        self.view.request.is_ajax.return_value = True
        self.view.kwargs = {
            'transaction': '123',
        }

        self.nut = SQRLNut.objects.create(
            nonce='hello',
            transaction_nonce='123',
            ip_address='127.0.0.1',
            is_transaction_complete=True,
        )

    def tearDown(self):
        self.nut and self.nut.delete()
        super(TestSQRLStatusView, self).tearDown()

    def test_get_success_url(self):
        self.assertEqual(
            self.view.get_success_url(),
            settings.LOGIN_REDIRECT_URL
        )

    def test_get_success_url_from_querystring(self):
        self.view.request.GET['url'] = '?next={}'.format(reverse('sqrl:login'))

        self.assertEqual(
            self.view.get_success_url(),
            reverse('sqrl:login'),
        )

    def test_get_success_url_complete_registration(self):
        self.view.request.GET['url'] = '?next={}'.format(reverse('sqrl:login'))
        self.view.request.user.is_authenticated.return_value = False
        self.view.request.session = {SQRL_IDENTITY_SESSION_KEY: ''}

        self.assertEqual(
            self.view.get_success_url(),
            reverse('sqrl:complete-registration') + '?next={}'.format(reverse('sqrl:login')),
        )

    def test_get_object_404(self):
        self.nut.delete()
        self.nut = None

        with self.assertRaises(Http404):
            self.view.get_object()

    def test_get_object(self):
        actual = self.view.get_object()

        self.assertIsInstance(actual, SQRLNut)
        self.assertEqual(actual.nonce, self.nut.nonce)
        self.assertEqual(actual.transaction_nonce, self.nut.transaction_nonce)

    def test_post(self):
        response = self.view.post(self.view.request, self.nut.transaction_nonce)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['content-type'], 'application/json')
        self.assertEqual(json.loads(response.content.decode('utf-8')), {
            'transaction_complete': True,
            'redirect_to': settings.LOGIN_REDIRECT_URL,
        })

    def test_post_not_ajax(self):
        self.view.request.is_ajax.return_value = False

        response = self.view.post(self.view.request, self.nut.transaction_nonce)

        self.assertEqual(response.status_code, 405)


class TestSQRLAuthView(test.TestCase):
    pass


class TestCompleteRegistrationView(test.TestCase):
    def setUp(self):
        super(TestCompleteRegistrationView, self).setUp()
        self.view = SQRLCompleteRegistrationView()
        self.username = 'foobartest'
        self.view.request = mock.MagicMock(
            method='POST',
            POST={
                'username': self.username,
            },
        )
        self.identity = SQRLIdentity(
            public_key='a' * 43,
            verify_unlock_key='b' * 43,
            server_unlock_key='c' * 43,
            is_enabled=True,
            is_only_sqrl=False,
        )
        self.view.request.session = {
            SQRL_IDENTITY_SESSION_KEY: serializers.serialize('json', [self.identity]),
        }

    def tearDown(self):
        SQRLIdentity.objects.filter(public_key=self.identity.public_key).delete()
        get_user_model().objects.filter(username=self.username).delete()
        super(TestCompleteRegistrationView, self).tearDown()

    def test_check_session_for_sqrl_identity_or_404(self):
        self.assertIsNone(self.view.check_session_for_sqrl_identity_or_404())

    def test_check_session_for_sqrl_identity_or_404_raises(self):
        self.view.request.session = {}

        with self.assertRaises(Http404):
            self.view.check_session_for_sqrl_identity_or_404()

    @mock.patch.object(SQRLCompleteRegistrationView, 'check_session_for_sqrl_identity_or_404')
    @mock.patch.object(FormView, 'get')
    def test_get(self, mock_super_get, mock_check_session_for_sqrl_identity_or_404):
        response = self.view.get(self.view.request)

        self.assertEqual(response, mock_super_get.return_value)
        mock_check_session_for_sqrl_identity_or_404.assert_called_once_with()

    @mock.patch.object(SQRLCompleteRegistrationView, 'check_session_for_sqrl_identity_or_404')
    @mock.patch.object(FormView, 'post')
    def test_post(self, mock_super_post, mock_check_session_for_sqrl_identity_or_404):
        response = self.view.post(self.view.request)

        self.assertEqual(response, mock_super_post.return_value)
        mock_check_session_for_sqrl_identity_or_404.assert_called_once_with()

    def test_get_success_url(self):
        self.assertEqual(
            self.view.get_success_url(),
            settings.LOGIN_REDIRECT_URL
        )

    def test_get_success_url_from_querystring(self):
        self.view.request.GET = {'next': reverse('sqrl:manage')}

        self.assertEqual(
            self.view.get_success_url(),
            reverse('sqrl:manage'),
        )

    @mock.patch(TESTING_MODULE + '.login')
    def test_form_valid(self, mock_login):
        form = self.view.get_form(self.view.get_form_class())
        form.is_valid()

        # sanity checks
        self.assertFalse(get_user_model().objects.filter(username=self.username).count())
        self.assertFalse(SQRLIdentity.objects.filter(public_key=self.identity.public_key).count())

        response = self.view.form_valid(form)
        user = get_user_model().objects.filter(username=self.username).first()

        self.assertIsNotNone(user)
        self.assertEqual(user.username, self.username)
        self.assertIsInstance(user.sqrl_identity, SQRLIdentity)
        self.assertEqual(user.sqrl_identity.public_key, self.identity.public_key)
        self.assertEqual(response.status_code, 302)

    def test_form_valid_could_not_decode_identity(self):
        self.view.request.session[SQRL_IDENTITY_SESSION_KEY] = ''
        response = self.view.form_valid(self.view.get_form(self.view.get_form_class()))

        self.assertEqual(response.status_code, 500)
