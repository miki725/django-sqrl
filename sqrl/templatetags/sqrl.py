# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django import template

from ..sqrl import SQRLInitialization


register = template.Library()


@register.assignment_tag(takes_context=True)
def sqrl_nut(context):
    return SQRLInitialization(context['request'])
