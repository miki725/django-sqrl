# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import json
import logging
from collections import OrderedDict
from pprint import pformat

from django.conf import settings
from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    HASH_SESSION_KEY,
    SESSION_KEY,
    login,
)
from django.contrib.sessions.middleware import SessionMiddleware
from django.core import serializers
from django.http import Http404, HttpResponse, QueryDict
from django.http.response import JsonResponse
from django.shortcuts import redirect
from django.views.generic import FormView, TemplateView, View

from .exceptions import TIF, TIFException
from .forms import (
    AuthQueryDictForm,
    GenerateQRForm,
    RandomPasswordUserCreationForm,
    RequestForm,
)
from .models import Nut, SQRLIdentity
from .sqrl import SQRLInitialization
from .utils import Base64, Encoder, QRGenerator, get_user_ip, sign_data


log = logging.getLogger(__name__)


class SQRLLoginView(TemplateView):
    template_name = 'sqrl/login.html'

    def get_context_data(self, **kwargs):
        context = super(SQRLLoginView, self).get_context_data(**kwargs)
        sqrl = SQRLInitialization(self.request)
        context.update({
            'sqrl': sqrl,
        })
        return context


class SQRLQRGeneratorView(FormView):
    form_class = GenerateQRForm
    http_method_names = ['get']
    get = FormView.post

    def get_form_kwargs(self):
        kwargs = super(SQRLQRGeneratorView, self).get_form_kwargs()
        kwargs.update({'data': self.request.GET})
        return kwargs

    def form_invalid(self, form):
        return HttpResponse(
            json.dumps(form.errors),
            status=400,
            content_type='application/json',
        )

    def form_valid(self, form):
        image = QRGenerator().generate_image(form.cleaned_data['url'])
        return HttpResponse(image, content_type='image/png')


class SQRLCheckView(View):
    def post(self, request, *args, **kwargs):
        return JsonResponse({
            'is_logged_in': request.user.is_authenticated(),
        })


class SQRLHTTPResponse(HttpResponse):
    def __init__(self, nut, data, *args, **kwargs):
        normalized_data = Encoder.normalize(self.sign_response(nut, data))
        content = self.construct_http_server_response(normalized_data)

        kwargs.setdefault('content_type', 'text/plain')

        super(SQRLHTTPResponse, self).__init__(content, *args, **kwargs)

        self['Content-Length'] = len(self.content)

        self.add_debug_headers(normalized_data)

        log.debug('Response encoded data:\n{}'
                  ''.format(content))
        log.debug('Response data:\n{}'
                  ''.format(pformat(normalized_data)))
        log.debug('Response TIF breakdown:\n{}'
                  ''.format(pformat(TIF(int(data['tif'], 16)).breakdown())))

    def sign_response(self, nut, data):
        if not nut:
            return data

        data['mac'] = sign_data(data, nut)

        return data

    def construct_http_server_response(self, data):
        return Encoder.base64_dumps(data)

    def add_debug_headers(self, normalized_data):
        if settings.DEBUG:
            for k, v in normalized_data.items():
                self['SQRL-{}'.format(k)] = v


class SQRLAuthView(View):
    http_method_names = ['post']

    def dispatch(self, request, *args, **kwargs):
        self.tif = TIF(0)
        try:
            return super(SQRLAuthView, self).dispatch(request, *args, **kwargs)
        except TIFException as e:
            self.tif = self.tif.update(e.tif)
            return self.render_to_response()

    def get_server_data(self, data=None):
        _data = OrderedDict((
            ('ver', 1),
            ('nut', self.nut_value),
            ('tif', self.tif.as_hex_string()),
            ('qry', self.request.get_full_path()),
            ('sfn', getattr(settings, 'SQRL_SERVER_FRIENDLY_NAME',
                            self.request.get_host().split(':')[0])[:64]),
        ))

        if data is not None:
            _data.update(data)

        return _data

    def render_to_response(self, data=None):
        return SQRLHTTPResponse(self.nut, self.get_server_data(data))

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
        self.nut = Nut.objects.filter(nonce=self.nut_value).first()

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

        self.session = None
        self.identity = self.payload_form.identity
        self.previous_identity = self.payload_form.previous_identity
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
        self.session = SessionMiddleware().SessionStore(self.nut.session_key)

        # user is already associated with identity
        # so we can login the user
        if self.identity.user_id:
            user = self.identity.user
            user.backend = 'django.contrib.auth.backends.ModelBackend'

            session_auth_hash = user.get_session_auth_hash()

            self.session[SESSION_KEY] = user.pk
            self.session[BACKEND_SESSION_KEY] = user.backend
            self.session[HASH_SESSION_KEY] = session_auth_hash

        # user was not found so lets save identity information in session
        # so that we can complete user registration
        else:
            serialized = serializers.serialize('json', [self.identity])
            self.session['_sqrl_identity'] = serialized
            log.debug('Storing sqrl identity in session to complete registration:\n{}'
                      ''.format(pformat(json.loads(serialized)[0]['fields'])))

    def disable(self):
        self.create_or_update_identity()
        self.identity.is_enabled = False

    def enable(self):
        self.create_or_update_identity()
        self.identity.is_enabled = True

    def finalize(self):
        if self.identity and self.identity.user_id:
            self.identity.save()
        if self.session:
            self.session.save()

    def create_or_update_identity(self):
        if hasattr(self, '_identity_updated'):
            return self.identity

        if not self.identity:
            self.identity = SQRLIdentity()

        self.identity.public_key = Base64.encode(self.client['idk'])
        self.identity.is_only_sqrl = 'sqrlonly' in self.client['opt']

        if self.client['vuk']:
            self.identity.verify_unlock_key = Base64.encode(self.client['vuk'])
        if self.client['suk']:
            self.identity.server_unlock_key = Base64.encode(self.client['suk'])

        return self.identity


class UserCreationView(FormView):
    form_class = RandomPasswordUserCreationForm
    template_name = 'sqrl/register.html'

    def check_session_for_sqrl_identity(self):
        if '_sqrl_identity' not in self.request.session:
            raise Http404

    def get(self, request, *args, **kwargs):
        self.check_session_for_sqrl_identity()
        return super(UserCreationView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.check_session_for_sqrl_identity()
        return super(UserCreationView, self).post(request, *args, **kwargs)

    def form_valid(self, form):
        try:
            identity = next(iter(serializers.deserialize(
                'json', self.request.session.pop('_sqrl_identity')
            ))).object
        except:
            return HttpResponse(status=500)

        user = form.save()
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        identity.user = user
        identity.save()

        login(self.request, user)

        return redirect('sqrl:login')
