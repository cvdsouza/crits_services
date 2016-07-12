import logging
import simplejson
import urllib
import urllib2
import urlparse
import requests

from hashlib import md5

from django.conf import settings
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError as DjangoValidationError

from crits.services.core import Service, ServiceConfigError
from crits.pcaps.handlers import handle_pcap_file
from crits.domains.handlers import upsert_domain
from crits.domains.domain import Domain
from crits.core.user_tools import get_user_organization
from crits.vocabulary.relationships import RelationshipTypes

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
    supported_types = ['Indicators', 'Domain', 'IP']
    required_fields = []
    description = "Look up a Sample, Domain or IP in VirusTotal"

    @staticmethod
    def bind_runtime_form(analyst, config):
        if 'vt_add_pcap' not in config:
            config['vt_add_pcap'] = False
        if 'vt_add_domains' not in config:
            config['vt_add_domains'] = False
        return forms.AlienVaultRunForm(config)

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.AlienVaultRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    @staticmethod
    def save_runtime_config(config):
        del config['vt_api_key']

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.VirusTotalConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def parse_config(config):
        if not config['vt_api_key']:
            raise ServiceConfigError("API key required.")

    @classmethod
    def generate_config_form(self, config):
        # Convert sigfiles to newline separated strings
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.VirusTotalConfigForm(initial=config),
                                 'config_error': None})
        form = forms.VirusTotalConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.VirusTotalConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config