import base64
import requests
import json
import time
import re
import logging
import socket

from django.conf import settings
from django.template.loader import render_to_string
from . import forms
from crits.services.core import Service, ServiceConfigError
from types import *

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
        if (config['url'] and not config['apiKey'] and not config['url_dump']) :
            raise ServiceConfigError("Must specify Punch++ URL, CheckMyDump URL and API Key.")

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

    def iprep_check(self,ip,config):

        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        url = config['url']
        api = config['apiKey']

        self._info("IP Address : "+ str(ip))

        match = re.match("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$", str(ip))
        if match.group(1):
            iprep_url_check = url + 'iprep_cidr.php/' + str(ip) + '?apikey=' + api
        else:
            iprep_url_check = url+'iprep.php/'+str(ip)+'?apikey='+api

        r = requests.get(iprep_url_check,verify=False, proxies= proxies)

        if r.status_code != 200:
            self._error("Response code not 200.")
            return
        data = {}
        results = r.json()
        self._add_result("Origin", results['origin'],)
        self._add_result("IP History","https://packetmail.net/iprep_history.php/"+str(ip)+"?apikey="+api)
        for mkey, subdict in results.iteritems():
            if 'context' in subdict  :

                data = {
                    "Source": subdict['source'],
                    "Context": subdict['context'],
                    "Last Seen": subdict['last_seen']
                }
                self._add_result("IP Reputation", mkey, data)

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

        self._info("Indicator Value : " + str(obj.value))

        #Validate IP Indicator
        match_ip = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", str(obj.value))

        # Validate URL Indicator
        regex_url = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        match_url = re.match(regex_url,str(obj.value))

        '''
        Check if Indicator is IPv4 or URL
        '''
        if match_ip:
            self._info("IPv4 Address : "+str(obj.value))
            self.iprep_check(obj.value, config)
        elif match_url:
            pcre_url_check = url + 'pcrematch.php?apikey=' + api+'&pcre_match_url='+str(obj.value)
            r = requests.get(pcre_url_check, verify=False, proxies=proxies)
            if r.status_code != 200:
                self._error("Response code not 200")
                return

            results = r.json()
            pcrematch = []
            try:
                bodyFlag = True if 'pcre' in results else False
                if type(results) is ListType:
                    for subval in results:
                        if 'pcre' in subval:
                            self._info(subval['pcre'])
                            pcrematch = subval['pcre']
                            self._add_result('PCRE Match', subval['pcre'])
            except IndexError:
                self._add_result('No PCRE Match')
        else:
            self._add_result("INCOMPATIBLE INDICATOR (IP or URL ONLY)", "INCOMPATIBLE INDICATOR")


    def run(self, obj, config):

        if obj._meta['crits_type'] == 'IP':
            self.iprep_check(obj.ip, config)
        elif obj._meta['crits_type'] == 'Indicator':
            self.pcre_match(obj,config)
        #elif obj._meta['crits_type'] == 'Email':
            #self.check_my_dump(obj,config)



