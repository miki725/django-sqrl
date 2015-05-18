# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import json
import logging
from collections import OrderedDict
from pprint import pformat

from braces.views._access import LoginRequiredMixin
from django.conf import settings
from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    HASH_SESSION_KEY,
    SESSION_KEY,
    login,
)
from django.core import serializers
from django.core.urlresolvers import reverse
from django.http import Http404, HttpResponse, JsonResponse, QueryDict
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import FormView, TemplateView, View

from .exceptions import TIF, TIFException
from .forms import (
    AuthQueryDictForm,
    ExtractedNextUrlForm,
    GenerateQRForm,
    NextUrlForm,
    RandomPasswordUserCreationForm,
    RequestForm,
)
from .models import SQRLIdentity, SQRLNut
from .response import SQRLHttpResponse
from .sqrl import SQRLInitialization
from .utils import Base64, QRGenerator, get_user_ip


SQRL_IDENTITY_SESSION_KEY = '_sqrl_identity'

log = logging.getLogger(__name__)


class SQRLLoginView(TemplateView):
    """
    Simple ``TemplateView`` which renders ``sqrl/login.html`` template.

    The template can (and probably should) be customized in each Django Project.

    .. note::
        This templates only provides SQRL auth method. If other methods are required
        on the same login page, it is probably better to add SQRL auth method to
        existing login page vs customizing this template/view.
    """
    template_name = 'sqrl/login.html'


class SQRLQRGeneratorView(FormView):
    """
    View for serving generated QR image for the SQRL link.

    The link is supplied via querystring ``url`` param which is then validated
    via :obj:`.forms.GenerateQRForm`.
    """
    form_class = GenerateQRForm
    http_method_names = ['get']

    def get(self, request, *args, **kwargs):
        """
        Custom ``get`` implementation which simply uses
        ``post`` since all form data should already be available
        in ``request.GET``.
        """
        return self.post(request, *args, **kwargs)

    def get_form_kwargs(self):
        """
        Get form kwargs with ``data`` using ``request.GET`` as input.
        """
        kwargs = super(SQRLQRGeneratorView, self).get_form_kwargs()
        kwargs.update({'data': self.request.GET})
        return kwargs

    def form_invalid(self, form):
        """
        Return ``400 Bad Request`` when invalid SQRL url is supplied.
        """
        return HttpResponse(
            json.dumps(form.errors),
            status=400,
            content_type='application/json',
        )

    def form_valid(self, form):
        """
        Return generated PNG QR image when url is successfully validated via form.
        """
        image = QRGenerator().generate_image(form.cleaned_data['url'])
        return HttpResponse(image, content_type='image/png')


class SQRLStatusView(View):
    """
    Ajax view which returns the status of the SQRL transaction back to the user.

    The state of the transaction is looked up by finding the appropriate
    :obj:`.models.SQRLNut` by the transaction ID which is a kwarg in the url pattern.
    When the nut is found, :attr:`.models.SQRLNut.is_transaction_complete` is
    used to determine the state of the transaction.

    This view is useful because when it returns a redirect upon successful completing
    of SQRL transaction, js can dynamically redirect the user to that page.
    Without this behaviour, user will have to manually refresh the page
    which is inconvenient.

    .. note::
        Currently this view is being used via polling on js side
        however this view's concept can easily be adopted to any other
        real-time technology such as websockets.
    """

    def get_success_url(self):
        """
        Get the url to which the user will be redirect to after
        successful SQRL transaction.

        The url is computed using :obj:`.forms.ExtractedNextUrlForm`.
        Following URLs are used depending if the form is valid:

        :``True``: Next url within the ``?url=`` querystring parameter
        :``False``: ``settings.LOGIN_REDIRECT_URL``

        When however the user is not logged in, even after successful
        SQRL transaction and has pending registration, user will be
        redirected to ``sqrl-complete-registration`` view with the
        ``?next=`` querystring parameter set to the url computed above.
        """
        next_form = ExtractedNextUrlForm(self.request.GET)

        if next_form.is_valid():
            url = next_form.cleaned_data['url']
        else:
            url = settings.LOGIN_REDIRECT_URL

        if all([not self.request.user.is_authenticated(),
                SQRL_IDENTITY_SESSION_KEY in self.request.session]):
            return reverse('sqrl:complete-registration') + '?next={}'.format(url)
        else:
            return url

    def get_object(self):
        """
        Get the :obj:`.models.SQRLNut` by transaction is or raise ``404``.
        """
        return get_object_or_404(SQRLNut, transaction_nonce=self.kwargs['transaction'])

    def post(self, request, transaction, *args, **kwargs):
        """
        Handle the request and return appropriate data back to the user.

        Following keys can be returned:

        :``transaction_complete``: boolean which is always returned
        :``redirect_to``: also present when ``transaction_complete == True``
                          and this is where the js should redirect the user to.

        .. note::
            This view is restricted to ajax calls as to restrict its
            use from regular forms.
        """
        if not request.is_ajax():
            return HttpResponse(status=405)  # method not allowed

        transaction = self.get_object()

        data = {
            'transaction_complete': False,
        }

        if transaction.is_transaction_complete:
            data.update({
                'transaction_complete': True,
                'redirect_to': self.get_success_url(),
            })

        return JsonResponse(data)


class SQRLAuthView(View):
    http_method_names = ['post']

    def dispatch(self, request, *args, **kwargs):
        self.tif = TIF(0)
        self.identity = None
        try:
            return super(SQRLAuthView, self).dispatch(request, *args, **kwargs)
        except TIFException as e:
            self.tif = self.tif.update(e.tif)
            return self.render_to_response()

    def get_server_data(self, data=None):
        if self.nut:
            self.nut.renew()
            nut = self.nut.nonce
            qry = SQRLInitialization(self.request, self.nut).url
        else:
            nut = self.nut_value
            qry = self.request.get_full_path()

        _data = OrderedDict((
            ('ver', 1),
            ('nut', nut),
            ('tif', self.tif.as_hex_string()),
            ('qry', qry),
            ('sfn', getattr(settings, 'SQRL_SERVER_FRIENDLY_NAME',
                            self.request.get_host().split(':')[0])[:64]),
        ))

        if self.identity:
            _data['suk'] = self.identity.server_unlock_key

        if data is not None:
            _data.update(data)

        return _data

    def render_to_response(self, data=None):
        return SQRLHttpResponse(self.nut, self.get_server_data(data))

    def do_ips_match(self):
        if get_user_ip(self.request) == self.nut.ip_address:
            self.tif = self.tif.update(TIF.IP_MATCH)

    def do_ids_match(self):
        if self.identity:
            self.tif = self.tif.update(TIF.ID_MATCH)

        if self.previous_identity:
            self.tif = self.tif.update(TIF.PREVIOUS_ID_MATCH)

    def is_sqrl_disabled(self):
        self.is_disabled = False

        if self.identity and not self.identity.is_enabled:
            self.tif = self.tif.update(TIF.SQRL_DISABLED)
            self.is_disabled = True

        if self.previous_identity and not self.previous_identity.is_enabled:
            self.tif = self.tif.update(TIF.SQRL_DISABLED)
            self.is_disabled = True

    def get_nut_or_error(self):
        self.nut = (SQRLNut.objects
                    .filter(nonce=self.nut_value,
                            is_transaction_complete=False)
                    .first())

        if not self.nut:
            log.debug('Nut not found')
            raise TIFException(TIF.TRANSIENT_FAILURE | TIF.COMMAND_FAILED)

        self.do_ips_match()

        return self.nut

    def post(self, request, *args, **kwargs):
        log.debug('-' * 50)
        log.debug('Raw request body:\n{}'.format(request.body))

        # in case content-type is not given in which case
        # request.POST will be empty in which case manually parse
        # raw request body
        if not request.POST:
            request.POST = QueryDict(request.body)

        # nut is not part of URL regex so validate it here
        # using a form and if not valid, return 404,
        # same as if nut would of been validated in URL regex
        self.query_form = AuthQueryDictForm(request.GET)
        if not self.query_form.is_valid():
            log.debug('Query form failed with {}'
                      ''.format(repr(self.query_form.errors)))
            raise Http404

        log.debug('Request payload:\n{}'
                  ''.format(pformat(request.POST)))

        self.nut_value = self.query_form.cleaned_data['nut']
        self.nut = self.get_nut_or_error()

        # validate the client data
        # this also validates submitted signatures and verifies
        # that echoed back server response was not altered
        self.payload_form = RequestForm(self.nut, request.POST)
        if not self.payload_form.is_valid():
            log.debug('Request payload validation failed with {}'
                      ''.format(repr(self.payload_form.errors)))
            raise TIFException(TIF.COMMAND_FAILED | TIF.CLIENT_FAILURE)

        log.debug('Request payload successfully parsed and validated:\n{}'
                  ''.format(pformat(self.payload_form.cleaned_data)))

        self.client = self.payload_form.cleaned_data['client']

        self.identity = self.payload_form.identity
        self.previous_identity = self.payload_form.previous_identity
        self.session = self.payload_form.session
        self.do_ids_match()
        self.is_sqrl_disabled()

        cmds = [getattr(self, i, None) for i in self.client['cmd']]

        if not all(cmds):
            raise TIFException(TIF.COMMAND_FAILED | TIF.NOT_SUPPORTED)

        for cmd in cmds:
            cmd()

        self.finalize()

        return self.render_to_response()

    def query(self):
        pass

    def ident(self):
        if self.is_disabled:
            return

        self.create_or_update_identity()

        # user is already logged in
        # so simply associate identity with the user
        if all((self.session.get(i) for i in
                [SESSION_KEY, BACKEND_SESSION_KEY, HASH_SESSION_KEY])):
            self.identity.user_id = self.session.get(SESSION_KEY)

        # user is already associated with identity
        # so we can login the user
        elif self.identity.user_id:
            user = self.identity.user
            user.backend = 'sqrl.backends.SQRLModelBackend'

            session_auth_hash = user.get_session_auth_hash()

            self.session[SESSION_KEY] = user.pk
            self.session[BACKEND_SESSION_KEY] = user.backend
            self.session[HASH_SESSION_KEY] = session_auth_hash

            log.info('Successfully authenticated user "{}" via SQRL'.format(user.username))

        # user was not found so lets save identity information in session
        # so that we can complete user registration
        else:
            serialized = serializers.serialize('json', [self.identity])
            self.session[SQRL_IDENTITY_SESSION_KEY] = serialized
            log.debug('Storing sqrl identity in session "{}" to complete registration:\n{}'
                      ''.format(self.session.session_key,
                                pformat(json.loads(serialized)[0]['fields'])))

        self.nut.is_transaction_complete = True

    def disable(self):
        self.create_or_update_identity()
        self.identity.is_enabled = False

        self.nut.is_transaction_complete = True

    def enable(self):
        self.create_or_update_identity()
        self.identity.is_enabled = True

        self.nut.is_transaction_complete = True

    def remove(self):
        self.identity.delete()
        self.identity = None

        self.nut.is_transaction_complete = True

    def finalize(self):
        if self.identity and self.identity.user_id:
            self.identity.save()
        if self.session:
            self.session.save()

    def create_or_update_identity(self):
        if not self.identity:
            self.identity = SQRLIdentity()

        # by this point form has validated that if the identity is being switched
        # all necessary signatures were provided and validated
        # so we can safely set the public key which will either
        # 1) set new public key for new identity associations
        # 2) overwrite the existing public key with the same public key
        # 3) overwrite the existing public key which by this point
        # is previous identity with new current identity
        self.identity.public_key = Base64.encode(self.client['idk'])
        self.identity.is_only_sqrl = 'sqrlonly' in self.client['opt']

        # form validation will make sure that these are supplied when
        # necessary (e.g. creating new identity)
        # the reason we don't simply want to always overwrite these is
        # because for already associated identities, client will not supply
        # them so we dont want to overwrite the model with empty values
        if self.client.get('vuk') and not self.identity.verify_unlock_key:
            self.identity.verify_unlock_key = Base64.encode(self.client['vuk'])
        if self.client.get('suk') and not self.identity.server_unlock_key:
            self.identity.server_unlock_key = Base64.encode(self.client['suk'])

        return self.identity


class SQRLCompleteRegistrationView(FormView):
    """
    This view is used to complete user registration.

    That happens when SQRL transaction is successfully completed
    however does not have account yet setup. In that case :obj:`.SQRLAuthView`
    stores SQRL identity information in the session which this view can use.
    To complete registration, a form is displayed to the user.
    When form is successfully filled out, this view creates a new user and
    automatically assigns the stored SQRL identity from the session to the
    new user.
    """
    form_class = RandomPasswordUserCreationForm
    template_name = 'sqrl/register.html'
    success_url = settings.LOGIN_REDIRECT_URL

    def check_session_for_sqrl_identity_or_404(self):
        """
        Check if the SQRL identity is stored within the session
        and if not, raise ``Http404``.
        """
        if SQRL_IDENTITY_SESSION_KEY not in self.request.session:
            raise Http404

    def get(self, request, *args, **kwargs):
        """
        Same as regular ``FormView`` except this also checks for identity within session
        by using :meth:`.check_session_for_sqrl_identity_or_404`.
        """
        self.check_session_for_sqrl_identity_or_404()
        return super(SQRLCompleteRegistrationView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        """
        Same as regular ``FormView`` except this also checks for identity within session
        by using :meth:`.check_session_for_sqrl_identity_or_404`.
        """
        self.check_session_for_sqrl_identity_or_404()
        return super(SQRLCompleteRegistrationView, self).post(request, *args, **kwargs)

    def get_success_url(self):
        """
        Get success url to which user will be redirected to when registration is complete.

        The url from the ``?next=`` is used if :obj:`.forms.NextUrlForm` is valid.
        Otherwise :attr:`.success_url` is used.
        """
        next_form = NextUrlForm(self.request.GET)
        if next_form.is_valid():
            return next_form.cleaned_data['next']
        return self.success_url

    def form_valid(self, form):
        """
        When registration form is valid, this method finishes up
        creating new user with new SQRL identity.

        It does the following:

        #. decodes the stored SQRL identity in the session.
           If this step fails, this method returns ``500`` response.
        #. saves the new user and assigned the decoded identity to it
        #. logs in the new user
        #. redirects to url returned by :meth:`.get_success_url`
        """
        try:
            identity = next(iter(serializers.deserialize(
                'json', self.request.session.pop(SQRL_IDENTITY_SESSION_KEY)
            ))).object
        except:
            return HttpResponse(status=500)

        user = form.save()
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        identity.user = user
        identity.save()

        login(self.request, user)

        log.info('Successfully registered and authenticated user '
                 '"{}" via SQRL'.format(user.username))

        return redirect(self.get_success_url())


class SQRLIdentityManagementView(LoginRequiredMixin, TemplateView):
    """
    Simple ``TemplateView`` which renders ``sqrl/manage.html`` template.

    The template can (and probably should) be customized in each Django Project.

    .. warning::
        Since this view is to exclusively manage SQRL identity,
        no other auth methods should be added to this template/view.
    """
    template_name = 'sqrl/manage.html'
