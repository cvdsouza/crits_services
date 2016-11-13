'''
Author : Clinton Dsouza

'''

import logging

import itertools
import simplejson
import urllib
import urllib2
import urlparse
import requests
import socket
import re

from hashlib import md5

from django.conf import settings
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError as DjangoValidationError
from crits.indicators.indicator import Indicator
from crits.vocabulary.indicators import IndicatorTypes

from crits.services.core import Service, ServiceConfigError
from . import forms

logger = logging.getLogger(__name__)


class IntelService(Service):

    '''
    Collect the following and display on one page :
    1. Related IP
    2. Related Domain
    3. Related Indicator
    4. Related Strings
    '''

    name = "intel_collation_service"
    version ='1.0.0'
    supported_types=['Domain', 'IP', 'Indicator', 'Sample']
    required_fields = []
    description ="Collate vital informaation : IP, Hash, Strings, Indicators, Domains regarding a sample"

    @staticmethod
    def parse_config(config):

        if (config['url'] and not config['apiKey']):
            raise ServiceConfigError("Specify a URL and API to transfer information (ignore for now")

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.IntelConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.IntelConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.IntelConfigForm(initial=config),
                                 'config_error': None})
        form = forms.IntelConfigForm
        return form, html

    def collate_intel(self, obj, config):
        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        indicators = []
        filehash_md5 = obj.md5
        filehash_sha256 = obj.sha256
        filehash_sha1 = obj.sha1
        filehash_impfuzzy = obj.impfuzzy


        self._add_result("Sample Information : MD5", filehash_md5)
        self._add_result("Sample Information : SHA1", filehash_sha1)
        self._add_result("Sample Information : SHA256", filehash_sha256)
        self._add_result("Sample Information : ImpFuzzy", filehash_impfuzzy)






    def run(self, obj, config):
        if obj._meta['crits_type'] == 'Sample':
            self.collate_intel(obj, config)
