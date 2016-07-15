import logging
import simplejson
import urllib
import urllib2
import urlparse
import requests
import socket

from hashlib import md5

from django.conf import settings
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError as DjangoValidationError

from crits.services.core import Service, ServiceConfigError


from . import forms

logger = logging.getLogger(__name__)

class AlienVaultOTXService(Service):
    '''
    Query the Alien Vault OTX for :
    1. Indicators
    2. Pulses
    '''

    name = "otx_alienvault_lookup"
    version = '1.0.0'
    supported_types = ['Indicators', 'Domain', 'IP', 'Sample']
    required_fields = []
    description = "Look up a Sample, Domain or IP in AlienVault OTX"

    @staticmethod
    def parse_config(config):
        # Must have both DT API key and DT Username or neither.
        if (config['av_url'] and not config['av_api']):
            raise ServiceConfigError("Must specify both AlienValut OTX API and username.")

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.AlienVaultConfigForm().fields
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
        fields = forms.AlienVaultConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.AlienVaultConfigForm(initial=config),
                                 'config_error': None})
        form = forms.AlienVaultConfigForm
        return form, html

    def check_indicators_ip(self,obj, config):
        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        url = config['av_url']
        api = config['av_api']

        '''
        Detect if IP address if IPv4 or IPv6
        '''
        try:
            '''
            Check if ipv4
            '''
            if socket.inet_aton(obj):
                self._info("IPv4 Address : "+str(obj.ip))
                request_url = url+'indicators/IPv4/'+str(obj.ip)+'/malware'
                r = requests.get(request_url, verify=False, proxies=proxies)

                if r.status_code !=200:
                    self._error("Response not OK")
                    return
                results = r.json()
                for i in results.get():
                    self._add_result("Related Malicious Hash",i.get('hash'))

            else:
                self._info("IPv4 Address : " + str(obj.ip))
                request_url = url + 'indicators/IPv6/' + str(obj.ip) + '/malware'
                r = requests.get(request_url, verify=False, proxies=proxies)

                if r.status_code != 200:
                    self._error("Response not OK")
                    return
                results = r.json()
                for i in results.get():
                    self._add_result("Related Malicious Hash", i.get('hash'))
        except socket.error:
            self._error("not IPv4 address")

    def run(self, obj, config):
        self.check_indicators_ip(obj, config)








