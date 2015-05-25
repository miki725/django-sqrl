# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import unittest
from collections import OrderedDict

import ed25519
import mock
import six
from django import forms, test
from django.contrib.auth import SESSION_KEY, get_user_model
from django.utils.timezone import now

from ..crypto import HMAC, Ed25519, generate_randomness
from ..forms import PasswordLessUserCreationForm, RequestForm
from ..models import SQRLIdentity, SQRLNut
from ..utils import Base64, Encoder


TESTING_MODULE = 'sqrl.forms'


class TestRequestForm(test.TestCase):
    def get_key_pair(self):
        signing_key, verifying_key = ed25519.create_keypair()
        signing_key = signing_key.to_bytes()
        verifying_key = verifying_key.to_bytes()

        return signing_key, verifying_key

    def _setup(self):
        hasattr(self, 'nut') and self.nut.delete()
        hasattr(self, 'user') and self.user.delete()
        hasattr(self, 'identity') and self.identity.delete()

        self.nut = SQRLNut(
            nonce=generate_randomness(),
            transaction_nonce=generate_randomness(),
            session_key=generate_randomness(20),
            is_transaction_complete=False,
            ip_address='127.0.0.1',
            timestamp=now(),
        )
        self.nut.save()

        self.user = get_user_model().objects.create(
            username='test_clean_session',
        )

        self.identity = SQRLIdentity(
            user_id=self.user.pk,
            public_key=Base64.encode(self.public_key),
            server_unlock_key=Base64.encode(self.server_unlock_key),
            verify_unlock_key=Base64.encode(self.verify_unlock_key),
            is_enabled=True,
            is_only_sqrl=False,
        )
        self.identity.save()

        self.server_data = OrderedDict([
            ('ver', 1),
            ('nut', self.nut.nonce),
            ('tif', '8'),
            ('qry', '/sqrl/auth/?nut=nonce'),
            ('sfn', 'Test Server'),
        ])
        self.server_data['mac'] = HMAC(self.nut, self.server_data).sign_data()
        self.server_data = Encoder.normalize(self.server_data)

        self.client_data = OrderedDict([
            ('ver', 1),
            ('cmd', self.cmd),
            ('opt', ['sqrlonly']),
        ])
        if self.include_idk:
            self.client_data['idk'] = self.public_key
        if self.include_pidk:
            self.client_data['pidk'] = self.previous_public_key
        if self.include_suk:
            self.client_data['suk'] = self.server_unlock_key
        if self.include_vuk:
            self.client_data['vuk'] = self.verify_unlock_key

        self.payload_client_data = Encoder.normalize(OrderedDict(
            (k, v if not isinstance(v, list) else '~'.join(v))
            for k, v in self.client_data.items()
        ))

        self.data = {
            'client': Encoder.base64_dumps(self.client_data),
            'server': Encoder.base64_dumps(self.server_data),
        }
        self.signable_data = (
            self.data['client'] + self.data['server']
        ).encode('ascii')
        if self.include_ids:
            self.data['ids'] = Ed25519(
                self.public_key, self.identity_key, self.signable_data
            ).sign_data()
        if self.include_pids:
            self.data['pids'] = Ed25519(
                self.previous_public_key, self.previous_identity_key, self.signable_data
            ).sign_data()
        if self.include_urs:
            self.data['urs'] = Ed25519(
                self.verify_unlock_key, self.unlock_key, self.signable_data
            ).sign_data()

        self.cleaned_data = self.data.copy()
        self.cleaned_data.update({
            'client': self.client_data,
            'server': self.server_data,
        })

        self.form = RequestForm(self.nut, data=self.data)

    def setUp(self):
        super(TestRequestForm, self).setUp()

        self.cmd = ['query']

        self.identity_key, self.public_key = self.get_key_pair()
        self.previous_identity_key, self.previous_public_key = self.get_key_pair()
        self.unlock_key, self.verify_unlock_key = self.get_key_pair()
        self.server_unlock_key = b'hello'

        self.include_idk = True
        self.include_pidk = True
        self.include_suk = True
        self.include_vuk = True
        self.include_ids = True
        self.include_pids = True
        self.include_urs = True

        self._setup()

    def tearDown(self):
        self.user and self.user.delete()
        self.identity and self.identity.delete()
        self.nut and self.nut.delete()
        super(TestRequestForm, self).tearDown()

    def test_init(self):
        form = RequestForm(mock.sentinel.nut)

        self.assertEqual(form.nut, mock.sentinel.nut)
        self.assertIsNone(form.session)
        self.assertIsNone(form.identity)
        self.assertIsNone(form.previous_identity)

    def test_clean_client(self):
        self.form.cleaned_data = {'client': self.payload_client_data}

        self.assertEqual(self.form.clean_client(), dict(self.client_data))

    def test_clean_client_invalid(self):
        self.form.cleaned_data = {
            'client': {
                'ver': '2',
            }
        }

        with self.assertRaises(forms.ValidationError):
            self.form.clean_client()

    def test_clean_server_not_dict(self):
        self.form.cleaned_data = {'server': mock.sentinel.server_data}

        self.assertEqual(self.form.clean_server(), mock.sentinel.server_data)

    def test_clean_server(self):
        self.form.cleaned_data = {
            'server': self.server_data
        }

        self.assertEqual(
            self.form.clean_server(),
            self.server_data
        )

    def test_clean_server_mac_not_base64(self):
        self.server_data['mac'] = 'hello'
        self.form.cleaned_data = {'server': self.server_data}

        with self.assertRaises(forms.ValidationError):
            self.form.clean_server()

    def test_clean_server_mismatch_nut(self):
        self.server_data['nut'] = self.server_data['nut'][::-1]
        self.form.cleaned_data = {'server': self.server_data}

        with self.assertRaises(forms.ValidationError):
            self.form.clean_server()

    def test_clean_server_mismatch_missing_mac(self):
        del self.server_data['mac']
        self.form.cleaned_data = {'server': self.server_data}

        with self.assertRaises(forms.ValidationError):
            self.form.clean_server()

    def test_clean_server_invalid_mac(self):
        self.server_data['mac'] = self.server_data['mac'][::-1]
        self.form.cleaned_data = {'server': self.server_data}

        with self.assertRaises(forms.ValidationError):
            self.form.clean_server()

    def test_clean_ids(self):
        self.form.cleaned_data = {
            'client': self.client_data,
            'ids': self.data['ids'],
        }

        self.assertEqual(
            self.form.clean_ids(),
            self.data['ids']
        )

    def test_clean_ids_invalid(self):
        self.form.cleaned_data = {
            'client': self.client_data,
            'ids': self.data['ids'][::-1],
        }

        with self.assertRaises(forms.ValidationError):
            self.form.clean_ids()

    def test_clean_pids_valid(self):
        self.form.cleaned_data = {
            'client': self.client_data,
            'pids': self.data['pids'],
        }

        self.assertEqual(
            self.form.clean_pids(),
            self.data['pids']
        )

    def test_clean_pids_invalid(self):
        self.form.cleaned_data = {
            'client': self.client_data,
            'pids': self.data['pids'][::-1],
        }

        with self.assertRaises(forms.ValidationError):
            self.form.clean_pids()

    def test_clean_pids_missing_pids(self):
        self.form.cleaned_data = {
            'client': self.client_data,
        }

        with self.assertRaises(forms.ValidationError):
            self.form.clean_pids()

    def test_clean_pids_missing_pidk(self):
        self.client_data.pop('pidk')
        self.form.cleaned_data = {
            'client': self.client_data,
            'pids': self.data['pids'],
        }

        with self.assertRaises(forms.ValidationError):
            self.form.clean_pids()

    def test_clean_urs(self):
        self.form.cleaned_data = self.cleaned_data
        self.form.identity = self.identity

        self.assertEqual(
            self.form._clean_urs(),
            self.data['urs']
        )

    def test_clean_urs_invalid(self):
        self.form.cleaned_data = {
            'client': self.client_data,
            'urs': self.data['urs'][::-1],
        }
        self.form.identity = self.identity

        with self.assertRaises(forms.ValidationError):
            self.form._clean_urs()

    def test_clean_urs_no_suk(self):
        self.form.cleaned_data = {
            'client': self.client_data,
            'urs': self.data['urs'],
        }
        self.form.identity = self.identity
        self.identity.server_unlock_key = None

        with self.assertRaises(forms.ValidationError):
            self.form._clean_urs()

    def test_clean_urs_no_vuk(self):
        self.form.cleaned_data = {
            'client': self.client_data,
            'urs': self.data['urs'],
        }
        self.form.identity = self.identity
        self.identity.verify_unlock_key = None

        with self.assertRaises(forms.ValidationError):
            self.form._clean_urs()

    def test_clean_cmd_query(self):
        self.cmd = ['query']
        self._setup()

        self.form.cleaned_data = {
            'client': self.client_data,
        }

        self.assertIsNone(self.form._clean_client_cmd())

    def test_clean_cmd_ident(self):
        self.cmd = ['ident']
        self._setup()

        self.form.cleaned_data = {
            'client': self.client_data,
        }

        self.assertIsNone(self.form._clean_client_cmd())

    def test_clean_cmd_ident_no_suk_vuk_without_identity(self):
        self.cmd = ['ident']
        self.include_suk = None
        self.include_vuk = None
        self._setup()

        self.form.cleaned_data = {
            'client': self.client_data,
        }

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_cmd_ident_suk_vuk_with_identity(self):
        self.cmd = ['ident']
        self._setup()

        self.form.identity = self.identity
        self.form.cleaned_data = {
            'client': self.client_data,
        }

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_cmd_ident_with_disable(self):
        self.cmd = ['ident', 'disable']
        self._setup()

        self.form.cleaned_data = {
            'client': self.client_data,
        }

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_cmd_ident_no_urs_with_previous_identity(self):
        self.cmd = ['ident']
        self._setup()

        self.form.previous_identity = self.identity
        self.form.cleaned_data = {
            'client': self.client_data,
        }

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_cmd_disable(self):
        self.cmd = ['disable']
        self._setup()

        self.form.identity = self.identity
        self.form.cleaned_data = {
            'client': self.client_data,
        }

        self.assertIsNone(self.form._clean_client_cmd())

    def test_clean_cmd_disable_no_identity(self):
        self.cmd = ['disable']
        self._setup()

        self.form.cleaned_data = {
            'client': self.client_data,
        }

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_cmd_disable_with_enable(self):
        self.cmd = ['disable', 'enable']
        self._setup()

        self.form.identity = self.identity
        self.form.cleaned_data = {
            'client': self.client_data,
        }

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_cmd_enable(self):
        self.cmd = ['enable']
        self._setup()

        self.form.identity = self.identity
        self.form.cleaned_data = self.cleaned_data

        self.assertIsNone(self.form._clean_client_cmd())

    def test_clean_cmd_enable_no_urs(self):
        self.cmd = ['enable']
        self.include_urs = False
        self._setup()

        self.form.identity = self.identity
        self.form.cleaned_data = self.cleaned_data

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_cmd_enable_no_identity(self):
        self.cmd = ['enable']
        self._setup()

        self.form.cleaned_data = self.cleaned_data

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_cmd_enable_with_disable(self):
        self.cmd = ['enable', 'disable']
        self._setup()

        self.form.identity = self.identity
        self.form.cleaned_data = self.cleaned_data

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_cmd_remove(self):
        self.cmd = ['remove']
        self._setup()

        self.form.identity = self.identity
        self.form.cleaned_data = self.cleaned_data

        self.assertIsNone(self.form._clean_client_cmd())

    def test_clean_cmd_remove_no_identity(self):
        self.cmd = ['remove']
        self._setup()

        self.form.cleaned_data = self.cleaned_data

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_cmd_remove_no_urs(self):
        self.cmd = ['remove']
        self.include_urs = False
        self._setup()

        self.form.identity = self.identity
        self.form.cleaned_data = self.cleaned_data

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_cmd_remove_with_other_cmd(self):
        self.cmd = ['remove', 'ident']
        self._setup()

        self.form.identity = self.identity
        self.form.cleaned_data = self.cleaned_data

        with self.assertRaises(forms.ValidationError):
            self.form._clean_client_cmd()

    def test_clean_session_empty(self):
        self.form.session = {}

        self.assertIsNone(self.form._clean_session())

    def test_clean_session_user_not_found(self):
        assert not get_user_model().objects.filter(pk=1000).first()

        self.form.session = {
            SESSION_KEY: '1000',
        }

        self.assertIsNone(self.form._clean_session())

    def test_clean_session_user_not_int(self):
        self.form.session = {
            SESSION_KEY: 'aaa',
        }

        self.assertIsNone(self.form._clean_session())

    def test_clean_session_no_sqrl_identity(self):
        self.identity.delete()
        self.identity = None
        self.form.session = {
            SESSION_KEY: six.text_type(self.user.pk),
        }

        self.assertIsNone(self.form._clean_session())

    def test_clean_session_public_key_not_matches(self):
        self.identity.public_key = self.identity.public_key[::-1]
        self.identity.save()

        self.form.session = {
            SESSION_KEY: six.text_type(self.user.pk),
        }
        self.form.cleaned_data = self.cleaned_data

        with self.assertRaises(forms.ValidationError):
            self.form._clean_session()

    def test_clean_session_user_code_mismatch(self):
        self.form.identity = self.identity
        self.form.session = {
            SESSION_KEY: six.text_type(self.user.pk + 1),
        }
        self.form.cleaned_data = self.cleaned_data

        with self.assertRaises(forms.ValidationError):
            self.form._clean_session()

    def test_clean(self):
        self.form.cleaned_data = self.cleaned_data

        actual = self.form.clean()

        self.assertEqual(actual, self.cleaned_data)

    @mock.patch.object(RequestForm, 'find_identities')
    @mock.patch.object(RequestForm, '_clean_client_cmd')
    @mock.patch.object(RequestForm, '_clean_urs')
    @mock.patch.object(RequestForm, 'find_session')
    @mock.patch.object(RequestForm, '_clean_session')
    @mock.patch.object(forms.Form, 'clean')
    def test_clean_mock(self,
                        mock_super_clean,
                        mock_clean_session,
                        mock_find_session,
                        mock_clean_urs,
                        mock_clean_client_cmd,
                        mock_find_identities):
        mock_super_clean.return_value = mock.sentinel.cleaned_data

        actual = self.form.clean()

        self.assertEqual(actual, mock.sentinel.cleaned_data)
        mock_super_clean.assert_called_once_with()
        mock_clean_session.assert_called_once_with()
        mock_find_session.assert_called_once_with()
        mock_clean_urs.assert_called_once_with()
        mock_clean_client_cmd.assert_called_once_with()
        mock_find_identities.assert_called_once_with()

    @mock.patch(TESTING_MODULE + '.SessionMiddleware')
    def test_find_session(self, mock_session_middleware):
        self.form.find_session()

        self.assertEqual(
            self.form.session,
            mock_session_middleware.return_value.SessionStore.return_value
        )
        mock_session_middleware.return_value.SessionStore.assert_called_once_with(
            self.nut.session_key,
        )

    def test_find_identities(self):
        self.form.cleaned_data = self.cleaned_data

        self.form.find_identities()

        self.assertIsNotNone(self.form.identity)
        self.assertIsInstance(self.form.identity, SQRLIdentity)
        self.assertEqual(self.form.identity.public_key, self.identity.public_key)
        self.assertIsNone(self.form.previous_identity)

    @mock.patch.object(RequestForm, '_get_identity')
    def test_find_identities_mock(self, mock_get_identity):
        self.form.cleaned_data = self.cleaned_data
        mock_get_identity.side_effect = mock.sentinel.identity, mock.sentinel.previous_identity

        self.form.find_identities()

        self.assertEqual(self.form.identity, mock.sentinel.identity)
        self.assertEqual(self.form.previous_identity, mock.sentinel.previous_identity)
        mock_get_identity.assert_has_calls([
            mock.call(self.public_key),
            mock.call(self.previous_public_key),
        ])

    @mock.patch(TESTING_MODULE + '.SQRLIdentity')
    def test_get_identity(self, mock_sqrl_identity):
        actual = self.form._get_identity(self.public_key)

        self.assertEqual(
            actual,
            mock_sqrl_identity.objects.filter.return_value.first.return_value
        )
        mock_sqrl_identity.objects.filter.assert_called_once_with(
            public_key=Base64.encode(self.public_key)
        )

    def test_get_identity_no_key(self):
        self.assertIsNone(self.form._get_identity(None))


class TestRandomPasswordUserCreationForm(unittest.TestCase):
    def test_init(self):
        self.assertIn('password1', PasswordLessUserCreationForm.base_fields)
        self.assertIn('password2', PasswordLessUserCreationForm.base_fields)

        form = PasswordLessUserCreationForm()

        self.assertNotIn('password1', form.fields)
        self.assertNotIn('password2', form.fields)

    def test_save(self):
        form = PasswordLessUserCreationForm({'username': 'test'})

        self.assertTrue(form.is_valid())

        user = form.save()

        self.assertEqual(user.username, 'test')
        self.assertTrue(user.password.startswith('!'))

        user.delete()
