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

class AlienVaultOTXService(Service):
    '''
    Query the Alien Vault OTX for :
    1. Indicators
    2. Pulses
    '''

    name = "otx_alienvault_lookup"
    version = '1.0.0'
    supported_types = ['Domain', 'IP', 'Indicator', 'Sample']
    required_fields = []
    template = 'avotx_service_template.html'
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

        indicators = []
        url = config['av_url']
        api = config['av_api']

        '''
        Detect if IP address if IPv4 or IPv6
        '''
        try:
            '''
            Check if ipv4
            '''

            if socket.inet_aton(str(obj.ip)):
                self._info("IPv4 Address : "+str(obj.ip))

                request_url = url+'indicators/IPv4/'+str(obj.ip)+'/malware'
                request_url_general = url + 'indicators/IPv4/' + str(obj.ip) + '/general'
                request_url_reputation = url + 'indicators/IPv4/' + str(obj.ip) + '/reputation'
                request_url_list = url + 'indicators/IPv4/' + str(obj.ip) + '/url_list'
                headers = {'X-OTX-API-KEY' : api}

                r = requests.get(request_url, headers=headers, verify=False, proxies=proxies)
                r_g = requests.get(request_url_general, headers=headers, verify=False, proxies=proxies)
                r_rp = requests.get(request_url_reputation, headers=headers, verify=False, proxies=proxies)
                r_url_list = requests.get(request_url_list, headers=headers, verify=False, proxies=proxies)

                if r.status_code !=200:
                    self._error("Response not OK")
                    return

                results = r.json()
                results_general = r_g.json()
                results_reputation = r_rp.json()
                results_url_list = r_url_list.json()

                geolocation = {
                    'Indicator': results_general.get('indicator'),
                    'Country': results_general.get('country_name'),
                    'whois': results_general.get('whois')
                }
                '''
                Simple Geolocation Data
                '''
                if geolocation is not None:
                    self._add_result("General Information", results_general.get('indicator'), geolocation)

                '''
                Related malware hashes.
                '''
                for i in results.get('data'):
                    self._add_result("Related Malicious Hash",i.get('hash'))
                '''
                Pulse Information
                '''
                if results_general.get('pulse_info') is not None:
                    for m,n in results_general.get('pulse_info').iteritems():
                        if 'pulses' in m and bool(n):
                            pulses = n
                            self._add_result("Pulses Found",str(obj.ip), pulses)

                '''
                Get reputational data
                '''
                activities = results_reputation['reputation']['activities']
                for active in activities:
                    self._add_result("IP Reputation-Activities",results_reputation['reputation']['address'], active)

                domains = results_reputation['reputation']['domains']
                for domain in domains:
                    indicators.append([domain, IndicatorTypes.DOMAIN])


                # Enable user to add unique indicators for this sample
                added = []
                for item in indicators:
                    if item[0]:
                        indicator = item[0].lower()
                        if indicator not in added:
                            added.append(indicator)
                            tdict = {}
                            if item[1] in (IndicatorTypes.IPV4_ADDRESS, IndicatorTypes.DOMAIN):
                                tdict = {'Type': item[1]}
                                id_ = Indicator.objects(value=indicator).only('id').first()
                                if id_:
                                    tdict['exists'] = str(id_.id)
                            self._add_result('add_alienvault_indicators', indicator, tdict)

                '''
                Get URL List :URLs analyzed by AlienVault Labs which point to or are somehow associated with this IP address.
                '''
                for lst in results_url_list['url_list']:
                    self._add_result("URL List","List", lst)


            else:

                self._info("IPv6 Address : " + str(obj.ip))

                request_url = url + 'indicators/IPv6/' + str(obj.ip) + '/malware'
                request_url_general = url + 'indicators/IPv6/' + str(obj.ip) + '/general'
                request_url_reputation = url + 'indicators/IPv6/' + str(obj.ip) + '/reputation'
                request_url_list = url + 'indicators/IPv6/' + str(obj.ip) + '/url_list'
                headers = {'X-OTX-API-KEY': api}

                r = requests.get(request_url, headers=headers, verify=False, proxies=proxies)
                r_g = requests.get(request_url_general, headers=headers, verify=False, proxies=proxies)
                r_rp = requests.get(request_url_reputation, headers=headers, verify=False, proxies=proxies)
                r_url_list = requests.get(request_url_list, headers=headers, verify=False, proxies=proxies)

                if r.status_code != 200:
                    self._error("Response not OK")
                    return

                results = r.json()
                results_general = r_g.json()
                results_reputation = r_rp.json()
                results_url_list = r_url_list.json()

                geolocation = {
                    'Indicator': results_general.get('indicator'),
                    'Country': results_general.get('country_name'),
                    'whois': results_general.get('whois')
                }
                '''
                Simple Geolocation Data
                '''
                if geolocation is not None:
                    self._add_result("General Information", results_general.get('indicator'), geolocation)

                '''
                Related malicious hashes.
                '''
                for i in results.get('data'):
                    self._add_result("Related Malicious Hash", i.get('hash'))
                '''
                Pulse Information
                '''
                if results_general.get('pulse_info') is not None:
                    for m, n in results_general.get('pulse_info').iteritems():
                        if 'pulses' in m and bool(n):
                            pulses = n
                            self._add_result("Pulses Found", str(obj.ip), pulses)

                '''
                Get reputational data
                '''
                activities = results_reputation['reputation']['activities']
                for active in activities:
                    self._add_result("IP Reputation-Activities", results_reputation['reputation']['address'], active)

                domains = results_reputation['reputation']['domains']
                for domain in domains:
                    indicators.append([domain, IndicatorTypes.DOMAIN])

                # Enable user to add unique indicators for this sample
                added = []
                for item in indicators:
                    if item[0]:
                        indicator = item[0].lower()
                        if indicator not in added:
                            added.append(indicator)
                            tdict = {}
                            if item[1] in (IndicatorTypes.IPV4_ADDRESS, IndicatorTypes.DOMAIN):
                                tdict = {'Type': item[1]}
                                id_ = Indicator.objects(value=indicator).only('id').first()
                                if id_:
                                    tdict['exists'] = str(id_.id)
                            self._add_result('add_alienvault_indicators', indicator, tdict)

                '''
                Get URL List :URLs analyzed by AlienVault Labs which point to or are somehow associated with this IP address.
                '''
                for lst in results_url_list['url_list']:
                    self._add_result("URL List", "List", lst)

        except socket.error:
            self._error("Couldn't establish connections or invalid IP address")

    def check_indicators_hostname(self,obj, config):

        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        indicators = []
        url = config['av_url']
        api = config['av_api']


        request_url = url + 'indicators/hostname/' + str(obj.domain) + '/malware'
        request_url_general = url + 'indicators/hostname/' + str(obj.domain) + '/general'
        request_url_reputation = url + 'indicators/hostname/' + str(obj.domain)+ '/reputation'
        request_url_list = url + 'indicators/hostname/' + str(obj.domain) + '/url_list'
        headers = {'X-OTX-API-KEY': api}
        r = requests.get(request_url, headers=headers, verify=False, proxies=proxies)
        r_g = requests.get(request_url_general, headers=headers, verify=False, proxies=proxies)
        r_rp = requests.get(request_url_reputation, headers=headers, verify=False, proxies=proxies)
        r_url_list = requests.get(request_url_list, headers=headers, verify=False, proxies=proxies)


        if r.status_code != 200:
            self._error("Response not OK")
            return

        results = r.json()
        results_general = r_g.json()
        results_reputation = r_rp.json()
        results_url_list = r_url_list.json()

        geolocation = {
            'Indicator': results_general.get('indicator'),
            'Country': results_general.get('country_name'),
            'whois': results_general.get('whois')
        }
        '''
        Simple Geolocation Data
        '''
        if geolocation is not None:
            self._add_result("General Information", results_general.get('indicator'), geolocation)

        '''
        Related malware hashes.
        '''
        if results.get('data') is not None:
            for i in results.get('data'):
                self._add_result("Related Malicious Hash", i.get('hash'))
        '''
        Pulse Information
        '''
        if results_general.get('pulse_info') is not None:
            for m, n in results_general.get('pulse_info').iteritems():
                if 'pulses' in m and bool(n):
                    pulses = n
                    self._add_result("Pulses Found", str(obj.ip), pulses)

        '''
        Get reputational data
        '''
        if 'reputation' in results_reputation:
            activities = results_reputation['reputation']['activities']
            for active in activities:
                self._add_result("Reputation-Activities", results_reputation['reputation']['address'], active)

            domains = results_reputation['reputation']['domains']
            for domain in domains:
                indicators.append([domain, IndicatorTypes.DOMAIN])

        # Enable user to add unique indicators for this sample
        added = []
        for item in indicators:
            if item[0]:
                indicator = item[0].lower()
                if indicator not in added:
                    added.append(indicator)
                    tdict = {}
                    if item[1] in (IndicatorTypes.IPV4_ADDRESS, IndicatorTypes.DOMAIN):
                        tdict = {'Type': item[1]}
                        id_ = Indicator.objects(value=indicator).only('id').first()
                        if id_:
                            tdict['exists'] = str(id_.id)
                    self._add_result('add_alienvault_indicators', indicator, tdict)

        '''
        Get URL List :URLs analyzed by AlienVault Labs which point to or are somehow associated with this IP address.
        '''
        for lst in results_url_list['url_list']:
            self._add_result("URL List", "List", lst)

    def check_indicators_url(self, obj, config):
        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        indicators = []
        url = config['av_url']
        api = config['av_api']

        regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

        regex_1 = re.compile(r'^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

        if regex.match(str(obj.value)) or regex_1.match(str(obj.value)):
            request_url_lst = url + 'indicators/url/' + str(obj.value) + '/url_list'
            request_url = url +'indicators/url/' + str(obj.value) + '/general'
            headers = {'X-OTX-API-KEY': api}
            r = requests.get(request_url, headers=headers, verify=False, proxies=proxies)
            r_lst = requests.get(request_url_lst, headers=headers, verify=False, proxies=proxies)

            if r_lst.status_code != 200:
                self._error("Response not OK")
                return

            results_lst = r_lst.json()
            results = r.json()

            self._add_result("General Information- Indicator", results.get('indicator'))
            self._add_result("General Information- Alexa",  results.get('alexa'))
            self._add_result("General Information- WHOIS",  results.get('whois'))
            self._add_result("General Information- Domain",  results.get('domain'))

            if results_lst.get('url_list') is not None:
                for i in results_lst.get('url_list'):
                    if i.get('result'):
                        self._add_result("URL Result",results_lst.get('net_loc'), i.get('result'))

        else:
            self._info("Indicator not a URL")


    def check_indicators_filehash(self, obj, config):
        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        indicators = []
        url = config['av_url']
        api = config['av_api']

        filehash = obj.md5

        request_url = url + 'indicators/file/' + str(filehash) + '/general'
        request_url_lst = url + 'indicators/file/' + str(filehash) + '/analysis'


        headers = {'X-OTX-API-KEY': api}
        r = requests.get(request_url, headers=headers, verify=False, proxies=proxies)

        if r.status_code != 200:
            self._error("Response not OK")
            return

        results = r.json()
        '''
        General Hash Information
        '''

        pulse_data = {}
        for mkey, subdict in results.iteritems():
            if 'pulses' in subdict:
                pulse_data = mkey, subdict['pulses']

        pulse_list = pulse_data[1]

        for item in pulse_list:
            name = item['name']
            author = item['author']
            self._add_result("General Information", name, author)

            if 'id' in item:
                if item['tags']:
                    d = dict(itertools.izip_longest(*[iter(item['tags'])] * 2, fillvalue=""))
                    self._add_result("Associated Metadata",name, d)
                    break



    def run(self, obj, config):
        if obj._meta['crits_type'] == 'IP':
            self.check_indicators_ip(obj, config)
        elif obj._meta['crits_type'] == 'Domain':
            self.check_indicators_hostname(obj,config)
        elif obj._meta['crits_type'] == 'Indicator':
            self.check_indicators_url(obj,config)
        elif obj._meta['crits_type'] == 'Sample':
            self.check_indicators_filehash(obj,config)








