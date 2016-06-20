import base64
import requests
import json
import time
import re
import logging

from django.conf import settings
from django.template.loader import render_to_string
from . import forms
from crits.services.core import Service, ServiceConfigError

logger = logging.getLogger(__name__)

class PunchService(Service):
    name = "punch"
    version = '1.0.0'
    supported_types = ['URL','IP']
    description = "Analyze IP reputation or malicious URL pcre"

    @staticmethod
    def parse_config(config):
        # Must have both DT API key and DT Username or neither.
        if (config['url'] and not config['apiKey']) :
            raise ServiceConfigError("Must specify both DT API and username.")

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.PunchplusplusConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.PunchplusplusConfigForm(initial=config),
                                 'config_error': None})
        form = forms.PunchplusplusConfigForm
        return form, html

    @staticmethod
    def save_runtime_config(config):
        if config['url']:
            del config['url']
        if config['apiKey']:
            del config['apiKey']

    @staticmethod
    def bind_runtime_form(analyst, config):

        form = forms.PunchplusplusRunForm(url=config['url'],
                                          apiKey=config['apiKey'])
        return form

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        html = render_to_string("services_run_form.html",
                                {'name': self.name,
                                 'form': forms.PunchplusplusRunForm(url=config['url'],
                                                            apiKey=config['apiKey']),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html

    def iprep_check(self,obj,config):
        url = config['url']
        api = config['apiKey']

        iprep_url_check = url+obj+'/'+api

        r = requests.get(iprep_url_check, proxies= self.proxies)

        if r.status_code != 200:
            self._error("Response code not 200.")
            return

        results = r.json()

        self._add_result("Result", results)

    def run(self, obj, config):
        if settings.HTTP_PROXY:
            self.proxies = {'http': settings.HTTP_PROXY,
                            'https': settings.HTTP_PROXY}
        else:
            self.proxies = {}

        if config['url'] and config['apiKey'] :
            self.iprep_check(obj, config)

