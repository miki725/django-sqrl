# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.db import models


class SQRLNutManager(models.Manager):
    """
    Customer :obj:`.models.SQRLNut` model manager.
    """

    def replace_or_create(self, session_key, **kwargs):
        """
        This method creates new :obj:`.models.SQRLNut` with given parameters.

        If nut already exists, it removes it before creating new nut.

        Parameters
        ----------
        session_key : str
            Key of the session. All nuts with matching session will be removed.
        **kwargs
            Kwargs which will be used to create new :obj:`.models.SQRLNut`
        """
        self.get_queryset().filter(session_key=session_key).delete()
        return self.create(session_key=session_key, **kwargs)
