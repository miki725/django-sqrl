# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import json
import logging
from collections import OrderedDict
from pprint import pformat

from django.conf import settings
from django.contrib.auth import login
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import Http404, HttpResponse, QueryDict
from django.http.response import JsonResponse
from django.views.generic import FormView, TemplateView, View

from .exceptions import TIF, TIFException
from .forms import AuthQueryDictForm, GenerateQRForm, RequestForm
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

        log.debug('Response status code is {}'.format(self.status_code))
        log.debug('Response headers:\n{}'
                  ''.format(pformat(sorted(self._headers.values()))))
        log.debug('Response data:\n{}'
                  ''.format(pformat(normalized_data)))
        log.debug('Response TIF breakdown:\n{}'
                  ''.format(pformat(TIF(int(data['tif'], 16)).breakdown())))
        log.debug('Response encoded data:\n{}'
                  ''.format(content))

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

    @property
    def session(self):
        if hasattr(self, '_session'):
            return self._session

        self._session = SessionMiddleware().SessionStore(self.nut.session_key)

        return self._session

    def login(self):
        login(self.request, self.nut.user)

    def do_ips_match(self):
        if get_user_ip(self.request) == self.nut.ip_address:
            self.tif = self.tif.update(TIF.IP_MATCH)

    def do_ids_match(self):
        if self.identity:
            self.tif = self.tif.update(TIF.ID_MATCH)

        if self.previous_identity:
            self.tif = self.tif.update(TIF.PREVIOUS_ID_MATCH)

    def is_disabled(self):
        if self.identity and not self.identity.is_enabled:
            self.tif = self.tif.update(TIF.SQRL_DISABLED)

        if self.previous_identity and not self.previous_identity.is_enabled:
            self.tif = self.tif.update(TIF.SQRL_DISABLED)

    def get_nut_or_error(self):
        self.nut = Nut.objects.filter(nonce=self.nut_value).first()

        if not self.nut:
            log.debug('Nut not found')
            raise TIFException(TIF.TRANSIENT_FAILURE | TIF.COMMAND_FAILED)

        self.do_ips_match()

        return self.nut

    def associate_identity(self):
        self.identity = SQRLIdentity.objects.create(
            public_key=Base64.encode(self.payload_form['client']['idk']),
            verify_unlock_key=Base64.encode(self.payload_form['client']['vuk']),
            server_unlock_key=Base64.encode(self.payload_form['client']['suk']),
        )

    def post(self, request, *args, **kwargs):
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

        self.identity = self.payload_form.identity
        self.previous_identity = self.payload_form.previous_identity
        self.do_ids_match()
        self.is_disabled()

        cmds = [getattr(self, i, None) for i in self.payload_form.cleaned_data['client']['cmd']]

        if not all(cmds):
            raise TIFException(TIF.COMMAND_FAILED | TIF.NOT_SUPPORTED)

        for cmd in cmds:
            cmd()

        return self.render_to_response()

    def query(self):
        pass

    def ident(self):
        pass

    def disable(self):
        pass

    def enable(self):
        pass
