===========
Django SQRL
===========

.. image:: https://travis-ci.org/miki725/django-sqrl.svg?branch=master
    :target: https://travis-ci.org/miki725/django-sqrl

.. image:: https://coveralls.io/repos/miki725/django-sqrl/badge.svg
    :target: https://coveralls.io/r/miki725/django-sqrl

SQRL authentication support for Django

* Free software: MIT license
* GitHub: https://github.com/miki725/django-sqrl
* Documentation: https://django-sqrl.readthedocs.org.

Installing
----------

SQRL Package
~~~~~~~~~~~~

First step is to install ``django-sqrl`` which is easies to do using pip::

    $ pip install django-sqrl

Django settings
~~~~~~~~~~~~~~~

Once installed there are a few required changes in Django settings:

#. Add ``sqrl`` to ``INSTALLED_APPS``::

      INSTALLED_APPS = [
          ...
          'sqrl',
      ]

#. Make sure that some required Django apps are used::

      INSTALLED_APPS = [
          ...,
          'django.contrib.auth',
          'django.contrib.sessions',
          'django.contrib.staticfiles',
          'sqrl',
      ]

#. Make sure that some required Django middleware are used::

      MIDDLEWARE_CLASSES = [
        ...
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
      ]

#. Change ``AUTHENTICATION_BACKENDS`` to use SQRL backend vs Django's ``ModelBackend`` (default)::

      AUTHENTICATION_BACKENDS = [
          'sqrl.backends.SQRLModelBackend',
      ]

Templates
~~~~~~~~~

Now that SQRL is installed in a Django project you can use it in any login page with a simple template code::

    {% sqrl as sqrl %}
    <a href="{{ sqrl.sqrl_url }}">
        <img src="{% sqrl_qr_image_url sqrl %}">
    </a>
    {% sqrl_status_url_script_tag sqrl %}
    <script src="{% static 'sqrl/sqrl.js' %}"></script>

The above template will add a QR image as a link which when used with SQRL client, will allow users to authenticate using SQRL.

Management Command
~~~~~~~~~~~~~~~~~~

SQRL uses server state to keep track of open SQRL transactions in order to mitigate replay attacks. Since this state will constantly grow if not cleared, ``django-sqrl`` provides a helper management command to clear expired state::

    $ python manage.py clearsqrlnuts

It is recommended to run this command as repeating task. Here is recommended cron config::

    */5 * * * * python manage.py clearsqrlnuts >/dev/null 2>&1

Testing
-------

To run the tests you need to install testing requirements first::

    $ make install

Then to run tests, you can use use Makefile command::

    $ make test
