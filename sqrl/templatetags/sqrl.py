# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django import template
from django.urls import reverse
from django.template.defaultfilters import urlencode

from ..sqrl import SQRLInitialization


register = template.Library()


@register.simple_tag(takes_context=True)
def sqrl(context):
    return SQRLInitialization(context['request'])


@register.simple_tag
def sqrl_qr_image_url(sqrl):
    return '{}?url={}'.format(reverse('sqrl:qr-image'), urlencode(sqrl.sqrl_url))


@register.simple_tag
def sqrl_status_url_script_tag(sqrl):
    url = reverse('sqrl:status', kwargs={'transaction': sqrl.nut.transaction_nonce})
    return '<script>SQRL_CHECK_URL="{url}"</script>'.format(url=url)


@register.simple_tag
def sqrl_status_url (sqrl):
    url = reverse('sqrl:status', kwargs={'transaction': sqrl.nut.transaction_nonce})
    return url
