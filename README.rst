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
        'sqrl',
        'django.contrib.auth',
        'django.contrib.sessions',
        'django.contrib.staticfiles',
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

#. If you are using Django admin, following are required:

   #. Make sure that ``sqrl`` is listed before ``admin`` in the ``INSTALLED_APPS``. This allows Django to prioritize ``sqrl`` templates since ``django-sqrl`` overwrites some of them.

      ::

        INSTALLED_APPS = [
            ...,
            'sqrl',
            'django.contrib.admin',
            ...
        ]

   #. Make sure to add a custom template directory in settings. ``django-sqrl`` extends Django admin's ``base.html`` which by default causes infinite recursion. To solve that, simply add a custom template directory which allows ``django-sqrl`` to explicitly extend from ``django.contrib.admin`` ``base.html`` template::

        import os
        import django
        TEMPLATE_DIRS = [
            os.path.dirname(django.__file__),
        ]

URLs
~~~~

All of SQRL functionality is enabled by adding its urls to the root url config::

    url(r'^sqrl/', include(sqrl_urlpatterns, namespace='sqrl')),

If you use Django admin, then you should also want to add some SQRL urls to admin urls so that SQRL identity can be managed within Django admin::

    from sqrl.views import AdminSiteSQRLIdentityManagementView
    url(r'^admin/sqrl_manage/$', AdminSiteSQRLIdentityManagementView.as_view(), name='admin-sqrl_manage'),
    url(r'^admin/', include(admin.site.urls)),

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

If you would like to also add explicit button to trigger SQRL client on desktop appliations, you can also use HTML form::

    {% sqrl as sqrl %}
    <form method="get" action="{{ sqrl.sqrl_url }}">
        {% sqrl_status_url_script_tag sqrl %}
        <a href="{{ sqrl.sqrl_url }}">
            <img src="{% sqrl_qr_image_url sqrl %}">
        </a>
        <input type="hidden" name="nut" value="{{ sqrl.nut.nonce }}">
        <input type="submit" value="Log in using SQRL">
    </form>
    {% sqrl_status_url_script_tag sqrl %}
    <script src="{% static 'sqrl/sqrl.js' %}"></script>

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
