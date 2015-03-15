# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals


def sqrl(request):
    return {
        'sqrl_identity': request.session.get('_sqrl_identity'),
    }
