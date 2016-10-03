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

__author__ =  "Clinton Dsouza"

logger = logging.getLogger(__name__)

class PunchService(Service):
    name = "punch_plus_plus_service"
    version = '1.0.1'
    supported_types = ['IP','Indicator']
    description = "Analyze IP reputation or malicious URL pcre"

    @staticmethod
    def parse_config(config):
        # Must have both Punch API key and Punch URL .
        if (config['url'] and not config['apiKey']) :
            raise ServiceConfigError("Must specify both Punch++ URL and API Key.")

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

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.PunchplusplusConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.PunchplusplusConfigForm(initial=config),
                                 'config_error': None})
        form = forms.PunchplusplusConfigForm
        return form, html

    def iprep_check(self,obj,config):

        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        url = config['url']
        api = config['apiKey']

        self._info("IP Address : "+ str(obj.ip))


        iprep_url_check = url+'iprep.php/'+str(obj.ip)+'?apikey='+api

        r = requests.get(iprep_url_check,verify=False, proxies= proxies)

        if r.status_code != 200:
            self._error("Response code not 200.")
            return

        results = r.json()
        self._add_result("Origin", results['origin'],)
        self._add_result("IP History","https://packetmail.net/iprep_history.php/"+str(obj.ip)+"?apikey="+api)
        for mkey, subdict in results.iteritems():
            if 'context' in subdict:
                self._add_result("IP Context", mkey, subdict)

        if 'MaxMind_Free_GeoIP' in results:
            geo={}
            for num in results.get('MaxMind_Free_GeoIP'):
                geo = {
                    "city": num['city'],
                    "Continent": num['continent_code'],
                    "Country": num['country_name']
                }
            self._add_result("Geo Location","Location" ,geo)

    def pcre_match(self, obj, config):
        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        url = config['url']
        api = config['apiKey']

        self._info("IP Address : " + str(obj.value))

        iprep_url_check = url + 'pcrematch.php?apikey=' + api+'&pcre_match_url='+str(obj.value)

        r = requests.get(iprep_url_check, verify=False, proxies=proxies)
        if r.status_code != 200:
            self._error("Response code not 200")
            return

        results = r.json()
        pcrematch = []
        try:
            if 'pcre' in results[1]:
                for subval in results:
                    if 'pcre' in subval:
                        self._info(subval['pcre'])
                        pcrematch = subval['pcre']
                        self._add_result('PCRE Match', subval['pcre'])
        except IndexError:
            self._add_result('No PCRE Match')


    def run(self, obj, config):

        if obj._meta['crits_type'] == 'IP':
            self.iprep_check(obj, config)
        elif obj._meta['crits_type'] == 'Indicator':
            self.pcre_match(obj,config)


