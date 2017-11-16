'''
Author : Clinton Dsouza

'''

import logging
import co3
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

    base_url = ''
    org_name = ''
    api_email = ''
    api_password= ''

    @staticmethod
    def parse_config(config):

        if (config['base_url'] and not config['org_name'] and not config['api_email'] and not config['api_password']):
            raise ServiceConfigError("Specify a URL, Org Name and Api Email and Password to transfer information (ignore for now")

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

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):

        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.IntelRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    @staticmethod
    def bind_runtime_form(analyst, config):
        """
        Set service runtime information
        """
        data = {'ticketNumber' : config['ticketNumber'][0]}

        return forms.IntelRunForm(data=data)



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
        sample_id = obj.id
        ticket_number = config['ticketNumber']
        if ticket_number is None:
            self._info("Empty, enter a ticket number")
        else:
            self._info("Ticket number %s" % ticket_number)


        self._add_result("Sample Information : MD5", filehash_md5)
        self._add_result("Sample Information : SHA1", filehash_sha1)
        self._add_result("Sample Information : SHA256", filehash_sha256)
        self._add_result("Sample Information : ImpFuzzy", filehash_impfuzzy)


        self._info("Entering Relationships ....")
        for rel in obj.relationships:
            if rel.rel_type == 'Indicator':
                indicator = Indicator.objects(id=rel.object_id).first()
                self._info("Print relationship value : %s " % indicator.value)
                self._info("Print relationship type : %s " % indicator.ind_type)
                post_value = self.push_to_resilient(ticket_number,indicator.value,indicator.ind_type,sample_id)
                self._add_result("Reslient Result", post_value)


    def push_to_resilient(self,ticket_number,indicator_value, indicator_type,crits_sample_id):

        client=co3.SimpleClient(org_name=str(self.org_name),base_url=str(self.base_url),verify=False)
        session = client.connect(str(self.api_email),str(self.api_password))

        inc_json = client.get("/incidents/{}/artifacts".format(str(ticket_number)))
        artifact_value=[]
        artifact_value_id=dict()
        value_post={}
        for i in inc_json:
            artifact_value_id[i['value']] = i['id']

        if indicator_value in artifact_value_id:

            artifact_value_update = {"description":"Artifact updated in CRITs"}
            artifact_id = artifact_value_id.get(indicator_value)
            value_update=client.put("/incidents/%s/artifacts/%s" % (str(ticket_number),str(artifact_id)), artifact_value_update)
            print "found"
        else:
            if indicator_type == "IPv4 Address":
                type = "IP Address"
                artifact_json = {"value": indicator_value, "type": type}
                value_post = client.post("/incidents/%s/artifacts",artifact_json)
            elif indicator_type == "Domain":
                type = "Domain"
                artifact_json = {"value": indicator_value, "type": type}
                value_post = client.post("/incidents/%s/artifacts", artifact_json)
            elif indicator_type == "URI":
                type = "URL"
                artifact_json = {"value": indicator_value, "type": type}
                value_post = client.post("/incidents/%s/artifacts", artifact_json)

        return value_post






    def run(self, obj, config):
        self.base_url = config.get('base_url', '')
        self.org_name = config.get('org_name', '')
        self.api_email = config.get('api_email', '')
        self.api_password = config.get('api_password', '')

        if obj._meta['crits_type'] == 'Sample':
            self.collate_intel(obj, config)
