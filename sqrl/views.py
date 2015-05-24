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
        image = QRGenerator(form.cleaned_data['url']).generate_image()
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
    success_url = settings.LOGIN_REDIRECT_URL

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
            url = self.success_url

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
    """
    This is the main view responsible for all interactions with SQRL client.

    The responsibilities of this view are:

    * validate that URL is correct since nut value is part of querystring
      which cannot be matched in url patterns.
      When invalid, 404 should be returned.
    * find the nut via nut nonce or return transient error TIF
    * validate client payload by using :obj:`.forms.RequestForm` which
      includes validating validity of signatures and looking up stored
      SQRL identities.
    * executing all SQRL commands such as ``query``, ``ident``, etc
      as instructed in the SQRL payload.
      If any of the commands are not supported not supported TIF
      is returned.
    * finalize the any remaining state such as saving identity objects
      if all commands successfully completed
    * returning response back to the user
    """
    http_method_names = ['post']

    def __init__(self, *args, **kwargs):
        super(SQRLAuthView, self).__init__(*args, **kwargs)

        self.tif = TIF(0)

        self.nut_value = None
        self.nut = None
        self.client = None
        self.identity = None
        self.previous_identity = None
        self.session = None
        self.is_disabled = False

    def dispatch(self, request, *args, **kwargs):
        """
        Standard ``dispatch`` with custom exception handling
        for :obj:`.exceptions.TIFException` in which error response is returned
        with TIF code as specified in the exception.
        """
        try:
            return super(SQRLAuthView, self).dispatch(request, *args, **kwargs)
        except TIFException as e:
            self.tif = self.tif.update(e.tif)
            return self.render_to_response()

    def get_server_data(self):
        """
        Get data to be returned back to SQRL client.

        This method does not encode for the response. It simply returns
        a dictionary of information which later on can be used by
        :obj:`.response.SQRLHttpResponse` to actually construct
        data to be sent back to the client.

        Returns
        -------
        OrderedDict
            Dict of data to be sent back to SQRL client.
            The ``Ordered`` part is important as SQRL requires
            to send some data first such as SQRL version number.
        """
        if self.nut:
            self.nut.renew()
            nut = self.nut.nonce
            qry = SQRLInitialization(self.request, self.nut).url
        else:
            nut = self.nut_value
            qry = self.request.get_full_path()

        data = OrderedDict((
            ('ver', 1),
            ('nut', nut),
            ('tif', self.tif.as_hex_string()),
            ('qry', qry),
            ('sfn', getattr(settings, 'SQRL_SERVER_FRIENDLY_NAME',
                            self.request.get_host().split(':')[0])[:64]),
        ))

        if self.identity:
            data['suk'] = self.identity.server_unlock_key

        return data

    def render_to_response(self):
        """
        Render a response which will be send to SQRL client.

        Internally this method uses :meth:`.get_server_data` to construct the response
        data and :obj:`.response.SQRLHttpResponse` to render that data into
        SQRL-compatible format.

        Returns
        -------
        SQRLHttpResponse
            Completely rendered response ready to the sent to the SQRL client
        """
        return SQRLHttpResponse(self.nut, self.get_server_data())

    def do_ips_match(self):
        """
        This method updates internal TIF state with :attr:`.exceptions.TIF.IP_MATCH` bit.

        The bit is only set when the IP address of the SQRL client making request
        to this view matches IP address of device used to initiate SQRL transation
        (where SQRL link/QR code were generated).
        """
        if get_user_ip(self.request) == self.nut.ip_address:
            self.tif = self.tif.update(TIF.IP_MATCH)

    def do_ids_match(self):
        """
        This method updates internal TIF state with :attr:`.exceptions.TIF.ID_MATCH`
        and :attr:`.exceptions.TIF.PREVIOUS_ID_MATCH` bits.

        The appropriate bits are only set when the the corresponding identity is found
        on the server.
        """
        if self.identity:
            self.tif = self.tif.update(TIF.ID_MATCH)

        if self.previous_identity:
            self.tif = self.tif.update(TIF.PREVIOUS_ID_MATCH)

    def is_sqrl_disabled(self):
        """
        This method updates internal TIF state with :attr:`.exceptions.TIF.SQRL_DISABLED` bit.

        The bit is only set when either current or previous identity are found
        and they have :attr:`.models.SQRLIdentity.is_enabled` set as ``False``
        which means previously SQRL client requested server to disable SQRL
        auth method for that user.

        Also this method sets ``self.is_disabled`` attribute which later on can be
        used by other methods to customize their behaviour.
        """
        self.is_disabled = False

        if self.identity and not self.identity.is_enabled:
            self.tif = self.tif.update(TIF.SQRL_DISABLED)
            self.is_disabled = True

        if self.previous_identity and not self.previous_identity.is_enabled:
            self.tif = self.tif.update(TIF.SQRL_DISABLED)
            self.is_disabled = True

    def get_nut_or_error(self):
        """
        This method finds the :obj:`.models.SQRLNut` by nut nonce in the
        querystring or if not not raises appropriate :obj:`.exceptions.TIFException`.

        When nut is found, it is saved as ``self.nut``. In addition, this method
        triggers :meth:`.do_ips_match` to update internal TIF state.

        Returns
        -------
        SQRLNut
            Found :obj:`.models.SQRLNut` via nut nonce from querystring

        Raises
        ------
        TIFException
            :obj:`.exceptions.TIFException` with :attr:`.exceptions.TIF.TRANSIENT_FAILURE`
            and :attr:`.exceptions.TIF.COMMAND_FAILED` bits sets as ``True``
            when nut is not found.
        """
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
        """
        Main view handler since all SQRL requests are ``POST`` requests.

        This method does not implement a lot of logic. It mostly relies on other
        methods which it then orchestrates. For information on what responsibilities
        which method has, you can take a look at :obj:`.SQRLAuthView` description.

        Some implementation details worth mentioning:

        * This method uses multiple forms to validate different sections of the payload.
          Specifically it uses :obj:`.forms.AuthQueryDictForm` to validate the presence
          of ``?nut=`` within querystring; and :obj:`.forms.RequestForm` to validate
          the SQRL payload itself.
        * This method extensively uses :obj:`.exceptions.TIFException` to immediately
          return some sort of error to the user which is handled by :meth:`.dispatch`.
          The only exception to that is that it still raises ``Http404`` when nut pattern
          is not validated. Normally in Django that would of been validated in url patterns
          however since SQRL forces to use ``?nut=`` querystring, we mimic same behaviour
          404 Not Found in the view.
        * To atomically process all SQRL commands (all or nothing), this view
          implements all SQRL commands as dedicated methods (e.g. :meth:`.query`).
          That allows this method to find all appropriate handlers for all the commands
          and if not all are found, :obj:`.exceptions.TIFException` can be raised
          with :attr:`.exceptions.TIF.NOT_SUPPORTED` bit set as ``True``.
          If all are found, then it simply processes them in the order they were requested.
        * Since any SQRL command can potentially fail, none of the SQRL command handlers
          save any state in either the session or models because other commands can fail
          after them. If all succeed, this method then explicitly finalizes/saves all the
          state which includes session and models.
        """
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
        """
        Handler for SQRL ``query`` command.

        Since all necessary information by default is already returned to the user,
        this method does not have to do anything.
        """

    def ident(self):
        """
        Handler for SQRL ``ident`` command.
        """
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
        """
        Handler for SQRL ``disable`` command.

        By the time this handler is called, :obj:`.forms.RequestForm` is already validated
        which guarantees that in order to use ``disable``, user must already have associated
        :obj:`.models.SQRLIdentity` so this method simply sets :attr:`.models.SQRLIdentity.is_enabled`
        to ``False``. Then if the rest of the SQRL commands succeed, :meth:`.finalize` will
        save that change.
        """
        self.create_or_update_identity()
        self.identity.is_enabled = False

        self.nut.is_transaction_complete = True

    def enable(self):
        """
        Handler for SQRL ``enable`` command.

        By the time this handler is called, :obj:`.forms.RequestForm` is already validated
        which guarantees that in order to use ``enable``, user must already have associated
        :obj:`.models.SQRLIdentity` and that the user correctly supplied ``urs`` signature.
        Therefore this method simply sets :attr:`.models.SQRLIdentity.is_enabled` to ``True``.
        Then if the rest of the SQRL commands succeed, :meth:`.finalize` will save that change.
        """
        self.create_or_update_identity()
        self.identity.is_enabled = True

        self.nut.is_transaction_complete = True

    def remove(self):
        """
        Handler for SQRL ``remove`` command.

        By the time this handler is called, :obj:`.forms.RequestForm` is already validated
        which guarantees that in order to use ``remove``, user must already have associated
        :obj:`.models.SQRLIdentity`, that the user correctly supplied ``urs`` signature
        and that that ``remove`` is the only command.
        Since all finalizing of the state should be handled by :meth:`.finalize`, this method
        does not actually delete the identity model but marks it for deletion.
        """
        self.identity.to_remove = True

        self.nut.is_transaction_complete = True

    def finalize(self):
        """
        State finalization method.

        This is necessary since SQRL can request multiple commands at the same time
        and any of them can fail. Therefore no state should be saved in any of the
        command handlers. They should adjust the state but not actually save it.
        Instead this method saves all the state. This allows the SQRL request
        processing to be atomic. Current it saves:

        * :obj:`.models.SQRLIdentity`
        * session data
        """
        if self.identity:
            if getattr(self.identity, 'to_remove', False):
                self.identity.delete()
            elif self.identity.user_id:
                self.identity.save()
        if self.session:
            self.session.save()

    def create_or_update_identity(self):
        """
        This method updates existing :obj:`.models.SQRLIdentity` or creates it
        when not already present.

        This is used to handle:

        * new users creating their :obj:`.models.SQRLIdentity` in which case
          all of the data will be set from scratch such as
          :attr:`.models.SQRLIdentity.public_key`, etc
        * existing users since they could be sending specific SQRL options
          (e.g. ``sqrlonly``) which should always update :obj:`.models.SQRLIdentity`
          depending on the presence of the options in the request.
        """
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

        Raises
        ------
        Http404
            When SQRL identity is not stored in session
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
        except Exception:
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
