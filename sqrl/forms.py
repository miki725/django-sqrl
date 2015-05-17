# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django import forms
from django.contrib.auth import SESSION_KEY, get_user_model
from django.contrib.auth.forms import UserCreationForm
from django.contrib.sessions.middleware import SessionMiddleware
from django.utils.crypto import get_random_string

from .crypto import HMAC, Ed25519
from .fields import (
    Base64ConditionalPairsField,
    Base64Field,
    Base64PairsField,
    ExtractedNextUrlField,
    NextUrlField,
    SQRLURLField,
    TildeMultipleValuesField,
)
from .models import SQRLIdentity
from .utils import Base64


class NextUrlForm(forms.Form):
    """
    Form which validates that next URL is a valid URL.

    Currently is used by :obj:`.views.SQRLCompleteRegistrationView` to validate
    next URL to which user will be redirected when registration is completed.
    """
    next = NextUrlField()


class ExtractedNextUrlForm(forms.Form):
    """
    Form which extracts and validates next URL from a full URL.

    Currently is used by :obj:`.views.SQRLStatusView` to return an appropriate
    URL to the JS to which JS will redirect to when SQRL transaction is complete.
    The reason we want to extract the next url here vs js is for simplicity
    of the js code. Now js can simply find ``<input name=next/>`` or if not present
    pass current full URL which might contain ``?next=<url>`` to the server.
    Python then can extract next url when present and if valid, return appropriate
    URL for the user to redirect to.
    """
    url = ExtractedNextUrlField()


class GenerateQRForm(forms.Form):
    """
    Form to validate SQRL url which which QR will be generated.

    We want a form here so that we can guarantee that QR code is being created
    for a URL value and not some random data.
    """
    url = SQRLURLField()


class AuthQueryDictForm(forms.Form):
    """
    Form to validate the ``request.GET`` in :obj:`.views.SQRLAuthView`.

    This allows to validate that the nut is of expected length and matches
    particular regex pattern before we attempt to look it up in the db.
    Normally this would be validated by a url pattern however in SQRL,
    nut is sent as a querystring parameter which is outside of the scope
    of URL pattern matching in Django.
    """
    nut = forms.RegexField(regex=r'[A-Za-z0-9-_]', min_length=43, max_length=43)


class ClientForm(forms.Form):
    """
    Form used to validate client portion of the SQRL request payload.

    Since this form is used as nested form by :obj:`.RequestForm`
    and therefore it does not have access to the signatures, this form
    only validates the values themselves. :obj:`.RequestForm` takes care
    of all conditional validations such as validating signatures
    when some keys are present in this form.
    """
    ver = forms.IntegerField(label='Version', min_value=1, max_value=1)
    cmd = TildeMultipleValuesField(label='Command')
    opt = TildeMultipleValuesField(label='Options', required=False)
    idk = Base64Field(label='Identity Key')
    pidk = Base64Field(label='Previous Identity Key', required=False)
    suk = Base64Field(label='Server Unlock Key', required=False)
    vuk = Base64Field(label='Verify Unlock Key', required=False)


class RequestForm(forms.Form):
    """
    This is a main form for validating SQRL request payload.

    This form uses uses :obj:`.ClientForm` for validating client portion of the request.
    Therefore some of the validation portions by the time they are executed,
    they expect client form to be validated so that they can lookup client values.
    Currently this does not require any *magic* solutions since ``client``
    is first defined field which means it will be validated first.

    Parameters
    ----------
    nut : SQRLNut
        Nut for which this form will be validated
    """
    client = Base64PairsField()
    server = Base64ConditionalPairsField()
    ids = Base64Field()
    pids = Base64Field(required=False)
    urs = Base64Field(required=False)

    def __init__(self, nut, *args, **kwargs):
        self.nut = nut
        self.session = None
        self.identity = None
        self.previous_identity = None
        super(RequestForm, self).__init__(*args, **kwargs)

    def clean_client(self):
        """
        Since Django forms dont support nested forms, this method is used
        to do that in ad-hoc fashion.

        By the time this method is called, we know that ``client`` data will be
        ``OrderedDict``, as guaranteed by :obj:`.fields.Base64PairsField`.
        We use that information and simply pass the client data to the
        :obj:`.ClientForm`. If validated, :obj:`.ClientForm` cleaned data will be
        a dictionary which we then simply return in this method. If not validated,
        we simply raise validation exception here which stop the rest of the
        validation steps.
        """
        client = self.cleaned_data['client']

        client_form = ClientForm(data=client)

        if not client_form.is_valid():
            raise forms.ValidationError(client_form.errors)

        return client_form.cleaned_data

    def clean_server(self):
        """
        This method conditionally validates ``server`` field.

        The reason why we validate it conditionally is because on initial SQRL
        request, client only sends initial SQRL URL since does not have access
        to the server response yet which would be a dict. In that case we do not
        validate server field at all.

        .. note::
            Even though on initial SQRL request, we dont validate server field,
            it is still indirectly validated against tampering via signatures.

        When we do validate it, we check the following:

        * nut value matches the looked up nut nonce
          (this should ever happen but just in case)
        * validate that ``mac`` is present in the server dict
        * validate the ``mac`` value that is correctly signs the server response
          excluding ``mac`` value itself.
        """
        server = self.cleaned_data['server']

        if not isinstance(server, dict):
            return server

        if server.get('nut') != self.nut.nonce:
            raise forms.ValidationError('Nut mismatch between server value and looked up nut.')

        if 'mac' not in server:
            raise forms.ValidationError('Missing server signature.')

        try:
            is_valid_signature = HMAC(self.nut, server).is_signature_valid(
                Base64.decode(server['mac'])
            )
        except ValueError:
            is_valid_signature = False

        if not is_valid_signature:
            raise forms.ValidationError('Invalid server signature.')

        return server

    def _validate_signature(self, name, key, signature):
        client = self.data['client']
        server = self.data['server']
        msg = (client + server).encode('ascii')

        if not Ed25519(key, msg).is_signature_valid(signature):
            raise forms.ValidationError('Invalid {} signature.'.format(name))

    def clean_ids(self):
        """
        Validate SQRL ID signature which always must be present.

        This validates that the ID signature correctly signed raw client + raw server
        concatenated base64 encoded strings.
        """
        idk = self.cleaned_data['client']['idk']
        ids = self.cleaned_data['ids']

        self._validate_signature('ids', idk, ids)

        return ids

    def clean_pids(self):
        """
        Validate Previous SQRL ID signature when present.

        This validates:

        * if either previous ID or previous signature are present, both are required
        * previous ID signature correctly signed raw client + raw server
          concatenated base64 encoded strings.
        """
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
        suk = client.get('suk')
        vuk = client.get('vuk')

        if not self.identity and not all([suk, vuk]):
            raise forms.ValidationError(
                'Missing suk or vuk which are required when creating new identity.'
            )

        if self.identity and any([suk, vuk]):
            raise forms.ValidationError(
                'Cannot send suk or vuk when SQRL identity is already associated.'
            )

        # since we only store a single identity at the time
        # its impossible for when identity is being changed
        # self.identity will exist since by definition server
        # should only be aware of the previous identity
        # since the client is sending a new identity for storage.
        if all((not self.identity,
                self.previous_identity,
                not self.cleaned_data.get('urs'))):
            raise forms.ValidationError(
                'Must supply urs (unlock request signature) when switching identities '
                'from previously stored identity (pidk) to new current identity (idk).'
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

    def _clean_client_cmd_remove(self, client):
        if not self.identity:
            raise forms.ValidationError(
                'Must have identity associated in order to remove SQRL.'
            )

        if not self.cleaned_data.get('urs'):
            raise forms.ValidationError(
                'Must supply urs (unlock request signature) to enable SQRL access.'
            )

    def _clean_session(self):
        user_model = get_user_model()

        user_id = self.session.get(SESSION_KEY)
        if not user_id:
            return

        user = user_model.objects.filter(pk=user_id).first()

        try:
            if not user or not user.sqrl_identity:
                return
        except SQRLIdentity.DoesNotExist:
            return

        # We want to make sure that if the user is logged in
        # and already has an identity associated with the account,
        # that either current or previous identity supplied in the
        # client request matches the identity already associated
        # with the account.
        # That will force the user to go through the SQRL identity
        # [un]lock processes to change the sqrl identity
        # (e.g. force the user to load the identity unlock key
        # and use that to change identities).
        # If this condition is not checked, it will be possible
        # for any SQRL identity to overwrite existing identity,
        # without any additional checks, which is not desirable.
        # For example if the existing auth scheme (e.g. username+password)
        # gets compromised, it will be possible for malicious party to
        # associate their SQRL identity with the account hence
        # locking out legitimate account owner.
        idk = Base64.encode(self.cleaned_data['client']['idk'])
        pidk = Base64.encode(self.cleaned_data['client'].get('pidk', b''))

        if user.sqrl_identity.public_key not in [idk, pidk]:
            raise forms.ValidationError(
                'Both current and previous identities do not match user\'s already '
                'associated SQRL identity. If the identity needs to be changed, '
                'SQRL identity unlock processes must be followed.'
            )

    def clean(self):
        """
        Assuming all fields successfully validated, this method validates form as a whole.

        Also this field does any db lookups such as retrieving SQRL identities.
        That is necessary for validation however since lookup already happens here,
        the :obj:`.views.SQRLAuthView` reuses the looked up values so that it
        does not have to lookup same objects twice.

        This method does the following (sometimes using private methods):

        #. lookups identities - both current and previous
        #. validates client commands (``client.cmd``) such as ``ident``.
           They can only be validated when identities are looked up.
           For example ``disable`` cannot be requested when no SQRL identity is found.
        #. validates ``urs`` (unlock request signature).
           That can only be done here as this requires to use data stored
           in the stored identity.
        #. lookups client session (where user will be logged in)
        #. validates session. For example if the user is already logged with existing
           matching SQRL identity, this validates that only stored SQRL identity
           public key can be used in SQRL transaction.
        """
        cleaned_data = super(RequestForm, self).clean()

        self.find_identities()
        self._clean_client_cmd()
        self._clean_urs()

        self.find_session()
        self._clean_session()

        return cleaned_data

    def find_session(self):
        """
        This method finds the session where SQRL transaction was initiated.

        This is the session where user potentially will be signed in.
        """
        self.session = SessionMiddleware().SessionStore(self.nut.session_key)

    def find_identities(self):
        """
        This method finds both current and previous SQRL identities.
        At most only one of them should be found.
        """
        self.identity = self._get_identity(self.cleaned_data['client']['idk'])
        self.previous_identity = self._get_identity(self.cleaned_data['client'].get('pidk'))

    def _get_identity(self, key):
        if not key:
            return None

        return SQRLIdentity.objects.filter(
            public_key=Base64.encode(key)
        ).first()


class RandomPasswordUserCreationForm(UserCreationForm):
    """
    Form for creating user account without password.

    This form is used when user successfully completes SQRL transaction
    however does not yet have a user account. Since they already successfully
    used SQRL, this implies that they they prefer to use SQRL over
    username/password. Django however requires password in order to create
    a user so we simply generate a random one. If the user will later wish
    to authenticate via password, they will need to follow password-reset
    procedure.
    """

    def __init__(self, *args, **kwargs):
        super(RandomPasswordUserCreationForm, self).__init__(*args, **kwargs)
        # loop over all the fields and remove all password fields
        # by default this removes both password and verify_password fields
        for field in self.fields:
            if 'password' in field:
                self.fields.pop(field)

    def clean(self):
        """
        This method assigns a random password when complete form is validated.
        """
        cleaned_data = super(RandomPasswordUserCreationForm, self).clean()

        # Create artificial password.
        # If user will want to use non-SQRL password,
        # they will need to reset the password.
        cleaned_data['password1'] = get_random_string(length=25)

        return cleaned_data
