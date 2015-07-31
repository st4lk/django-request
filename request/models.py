# -*- coding: utf-8 -*-
from socket import gethostbyaddr
import logging

from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _

from request.managers import RequestManager
from request.utils import HTTP_STATUS_CODES, browsers, engines
from request import settings as request_settings

l = logging.getLogger(__name__)

AUTH_USER_MODEL = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')
CUT_DATA_INDEX = getattr(settings, 'REQUST_LOG_CUT_DATA_INDEX', 8192)


class Request(models.Model):
    # Response infomation
    response = models.SmallIntegerField(_('response'), choices=HTTP_STATUS_CODES, default=200)
    response_code = models.SmallIntegerField(u'Код ответа', default=200)

    # Request infomation
    method = models.CharField(_('method'), default='GET', max_length=7)
    path = models.CharField(_('path'), max_length=255)
    time = models.DateTimeField(_('time'), auto_now_add=True)

    is_secure = models.BooleanField(_('is secure'), default=False)
    is_ajax = models.BooleanField(_('is ajax'), default=False, help_text=_('Wheather this request was used via javascript.'))

    # User infomation
    ip = models.GenericIPAddressField(_('ip address'))
    user = models.ForeignKey(AUTH_USER_MODEL, blank=True, null=True, verbose_name=_('user'))
    referer = models.URLField(_('referer'), max_length=255, blank=True, null=True)
    user_agent = models.CharField(_('user agent'), max_length=255, blank=True, null=True)
    language = models.CharField(_('language'), max_length=255, blank=True, null=True)

    # Detailed data
    request_get = models.TextField(blank=True, null=True)
    request_post = models.TextField(blank=True, null=True)
    request_body = models.TextField(blank=True, null=True)

    response_content = models.TextField(blank=True, null=True)
    response_data = models.TextField(blank=True, null=True)

    objects = RequestManager()

    class Meta:
        verbose_name = _('request')
        verbose_name_plural = _('requests')
        ordering = ('-time',)

    def __str__(self):
        return '[%s] %s %s %s' % (self.time, self.method, self.path, self.response)

    def get_user(self):
        return get_user_model().objects.get(pk=self.user_id)

    def from_http_request(self, request, response=None, commit=True):
        # Request infomation
        self.method = request.method
        self.path = request.path[:255]

        self.is_secure = request.is_secure()
        self.is_ajax = request.is_ajax()

        # User infomation
        self.ip = request.META.get('REMOTE_ADDR', '')
        self.referer = request.META.get('HTTP_REFERER', '')[:255]
        self.user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]
        self.language = request.META.get('HTTP_ACCEPT_LANGUAGE', '')[:255]

        if getattr(request, 'user', False):
            if request.user.is_authenticated():
                self.user = request.user

        if response:
            self.response = response.status_code
            self.response_code = response.status_code

            if (response.status_code == 301) or (response.status_code == 302):
                self.redirect = response['Location']

            try:
                if response.content:
                    try:
                        data = response.content.decode('utf-8')
                    except UnicodeDecodeError:
                        data = str(response.content)
                    self.response_content = data[:CUT_DATA_INDEX]
            except:
                l.exception("Something terrible happend during loggin response.content")

            try:
                if hasattr(response, 'data'):
                    self.response_data = str(response.data)[:CUT_DATA_INDEX]
            except:
                l.exception("Something terrible happend during loggin response.data")

        try:
            if request.GET:
                self.request_get = str(request.GET)[:CUT_DATA_INDEX]
        except:
            l.exception("Something terrible happend during logging request.GET")

        try:
            if request.POST:
                self.request_post = str(request.POST)[:CUT_DATA_INDEX]
        except:
            l.exception("Something terrible happend during logging request.POST")

        try:
            if request.body:
                self.request_body = str(request.body)[:CUT_DATA_INDEX]
        except:
            l.exception("Something terrible happend during logging request.body")

        if commit:
            self.save()

    @property
    def browser(self):
        if not self.user_agent:
            return

        if not hasattr(self, '_browser'):
            self._browser = browsers.resolve(self.user_agent)
        return self._browser[0]

    @property
    def keywords(self):
        if not self.referer:
            return

        if not hasattr(self, '_keywords'):
            self._keywords = engines.resolve(self.referer)
        if self._keywords:
            return ' '.join(self._keywords[1]['keywords'].split('+'))

    @property
    def hostname(self):
        try:
            return gethostbyaddr(self.ip)[0]
        except Exception:  # socket.gaierror, socket.herror, etc
            return self.ip

    def save(self, *args, **kwargs):
        if not request_settings.REQUEST_LOG_IP:
            self.ip = request_settings.REQUEST_IP_DUMMY
        elif request_settings.REQUEST_ANONYMOUS_IP:
            parts = self.ip.split('.')[0:-1]
            parts.append('1')
            self.ip='.'.join(parts)
        if not request_settings.REQUEST_LOG_USER:
            self.user = None

        super(Request, self).save(*args, **kwargs)
