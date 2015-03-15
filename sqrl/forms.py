# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.utils.crypto import get_random_string

from .fields import (
    Base64ConditionalPairsField,
    Base64Field,
    Base64PairsField,
    SQRLURLField,
    TildeMultipleValuesField,
)
from .models import SQRLIdentity
from .utils import Base64, sign_data, verify_signature


class GenerateQRForm(forms.Form):
    url = SQRLURLField()


class AuthQueryDictForm(forms.Form):
    nut = forms.RegexField(regex=r'[A-Za-z0-9-_]', min_length=43, max_length=43)


class ClientForm(forms.Form):
    ver = forms.IntegerField(label='Version', min_value=1, max_value=1)
    cmd = TildeMultipleValuesField(label='Command')
    opt = TildeMultipleValuesField(label='Options', required=False)
    idk = Base64Field(label='Identity Key')
    pidk = Base64Field(label='Previous Identity Key', required=False)
    suk = Base64Field(label='Server Unlock Key', required=False)
    vuk = Base64Field(label='Verify Unlock Key', required=False)


class RequestForm(forms.Form):
    client = Base64PairsField()
    server = Base64ConditionalPairsField()
    ids = Base64Field()
    pids = Base64Field(required=False)
    urs = Base64Field(required=False)

    def __init__(self, nut, *args, **kwargs):
        self.nut = nut
        self.identity = None
        self.previous_identity = None
        super(RequestForm, self).__init__(*args, **kwargs)

    def clean_client(self):
        client = self.cleaned_data['client']

        client_form = ClientForm(data=client)

        if not client_form.is_valid():
            raise forms.ValidationError(client_form.errors)

        return client_form.cleaned_data

    def clean_server(self):
        server = self.cleaned_data['server']

        if not isinstance(server, dict):
            return server

        if server.get('nut') != self.nut.nonce:
            raise forms.ValidationError('Nut mismatch between server value and looked up nut.')

        if 'mac' not in server:
            raise forms.ValidationError('Missing server signature.')

        is_valid_signature = True
        signature = sign_data(server, self.nut)

        try:
            if signature != Base64.decode(server['mac']):
                is_valid_signature = False
        except ValueError:
            is_valid_signature = False

        if not is_valid_signature:
            raise forms.ValidationError('Invalid server signature.')

        return server

    def _validate_signature(self, name, key, signature):
        client = self.data['client']
        server = self.data['server']
        msg = (client + server).encode('ascii')

        if not verify_signature(key, signature, msg):
            raise forms.ValidationError('Invalid {} signature.'.format(name))

    def clean_ids(self):
        idk = self.cleaned_data['client']['idk']
        ids = self.cleaned_data['ids']

        self._validate_signature('ids', idk, ids)

        return ids

    def clean_pids(self):
        pidk = self.cleaned_data['client'].get('pidk')
        pids = self.cleaned_data.get('pids')

        if pids and not pidk:
            raise forms.ValidationError('pids is passed without pidk.')
        elif pidk and not pids:
            raise forms.ValidationError('pids is required when pidk is provided.')

        if pidk and pids:
            self._validate_signature('pids', pidk, pids)

        return pids

    def _clean_urs(self):
        vuk = getattr(self.identity, 'verify_unlock_key', None)
        suk = getattr(self.identity, 'server_unlock_key', None)

        urs = self.cleaned_data.get('urs')

        if urs:
            if not all((vuk, suk)):
                raise forms.ValidationError(
                    'Cannot validate urs signature without server knowing vuk and suk keys.'
                )

            self._validate_signature('urs', vuk, urs)

        return urs

    def _clean_client_cmd(self):
        client = self.cleaned_data['client']
        cmds = client['cmd']

        for cmd in cmds:
            method_name = '_clean_client_cmd_{}'.format(cmd)
            if hasattr(self, method_name):
                getattr(self, method_name)(client)

    def _clean_client_cmd_ident(self, client):
        if all((not self.identity,
                any((not client.get('suk'),
                     not client.get('vuk'))))):
            raise forms.ValidationError(
                'Missing suk or vuk which are required when creating new identity.'
            )

    def _clean_client_cmd_disable(self, client):
        if not self.identity:
            raise forms.ValidationError(
                'Must have identity associated in order to disable SQRL.'
            )

    def _clean_client_cmd_enable(self, client):
        if not self.identity:
            raise forms.ValidationError(
                'Must have identity associated in order to enable SQRL.'
            )

        if not self.cleaned_data.get('urs'):
            raise forms.ValidationError(
                'Must supply urs (unlock request signature) to enable SQRL access.'
            )

    def clean(self):
        cleaned_data = super(RequestForm, self).clean()

        self.get_identities()
        self._clean_client_cmd()
        self._clean_urs()

        return cleaned_data

    def _get_identity(self, key):
        if not key:
            return None

        return SQRLIdentity.objects.filter(
            public_key=Base64.encode(key)
        ).first()

    def get_identities(self):
        self.identity = self._get_identity(self.cleaned_data['client']['idk'])
        self.previous_identity = self._get_identity(self.cleaned_data['client'].get('pidk'))


class RandomPasswordUserCreationForm(UserCreationForm):
    def __init__(self, *args, **kwargs):
        super(RandomPasswordUserCreationForm, self).__init__(*args, **kwargs)
        for field in self.fields:
            if 'password' in field:
                self.fields.pop(field)

    def clean(self):
        cleaned_data = super(RandomPasswordUserCreationForm, self).clean()

        # Create artificial password.
        # If user will want to use non-SQRL password,
        # they will need to reset the password.
        cleaned_data['password1'] = get_random_string(length=25)

        return cleaned_data
