# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django import template
from django.core.urlresolvers import reverse
from django.template.defaultfilters import urlencode

from ..sqrl import SQRLInitialization


register = template.Library()


@register.assignment_tag(takes_context=True)
def sqrl(context):
    return SQRLInitialization(context['request'])


@register.simple_tag
def sqrl_qr_image_url(sqrl):
    return '{}?url={}'.format(reverse('sqrl:qr-image'), urlencode(sqrl.url))
