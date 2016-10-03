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
    name = "punchIPRep_service"
    version = '1.0.0'
    supported_types = ['IP','Indicator']
    description = "Analyze IP reputation or malicious URL pcre"

    @staticmethod
    def parse_config(config):
        # Must have both Punch API key and Punch URL .
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
    '''
    @staticmethod
    def save_runtime_config(config):
        if config['url']:
            del config['url']
        if config['apiKey']:
            del config['apiKey']

    @staticmethod
    def bind_runtime_form(analyst, config):

        form = forms.PunchplusplusRunForm(pydat_url=config['url'],
                                  dt_api_key=config['apiKey'],
                                  data=config)
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
    '''



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
        if 'pcre' in results[1]:
            for subval in results:
                if 'pcre' in subval:
                    self._info(subval['pcre'])
                    pcrematch = subval['pcre']
                    self._add_result('PCRE Match', subval['pcre'])



        else:
            self._add_result ('PCRE Match NOT FOUND')



    def run(self, obj, config):

        if obj._meta['crits_type'] == 'IP':
            self.iprep_check(obj, config)
        elif obj._meta['crits_type'] == 'Indicator':
            self.pcre_match(obj,config)


