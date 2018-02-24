import requests
import re
import logging
import json


from django.conf import settings
from django.template.loader import render_to_string
from . import forms
from crits.services.core import Service, ServiceConfigError
from types import *

__author__ =  "Clinton Dsouza"

logger = logging.getLogger(__name__)

class ThreatStreamService(Service):
    name = "threatstream_service"
    version = '1.0.0'
    supported_types = ['Sample','IP','Indicator', 'Domain']
    description = "Analyze IP reputation or malicious URL pcre"

    @staticmethod
    def parse_config(config):
        # Must have both Punch API key and Punch URL .
        if (config['url'] and not config['apiKey'] and not config['user_email']) :
            raise ServiceConfigError("Must specify API Key, URL and Username.")

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.ThreatStreamConfigForm().fields
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
        fields = forms.ThreatStreamConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.ThreatStreamConfigForm(initial=config),
                                 'config_error': None})
        form = forms.ThreatStreamConfigForm
        return form, html

    def ip_intelligence(self,ip,config):

        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        url = config['url']
        api = config['apiKey']
        user= config['user_email']

        self._info("IP Address : "+ str(ip))

        match = re.match("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$", str(ip))
        if match.group(0):
            ip_check = url+'/intelligence/?username=' + user +'&ip='+str(ip)+ '&api_key=' + api + '&limit=25'

            r = requests.get(ip_check, headers={'ACCEPT': 'application/json'}, verify=True, proxies= proxies)

            if r.status_code != 200:
                self._error("Response code not 200.")
                return
            data = {}
            self._info("Status : %s" %r.status_code)
            self._info("JSON : %s" %r.json())
            results = r.json()
            objects = results['objects']
            domain = 'N/A'
            itype = 'N/A'
            confidence = 'N/A'
            severity = 'N/A'
            source = 'N/A'
            date_last = 'N/A'
            md5 = 'N/A'
            url = 'N/A'
            country = 'N/A'
            for i in objects:
                if 'domain' in i:
                    domain = i['domain']
                if 'itype' in i:
                    itype = i['itype']
                if 'confidence' in i:
                    confidence = i['confidence']
                if 'severity' in i:
                    severity = i['severity']
                if 'source' in i:
                    source = i['source']
                if 'date_last' in i:
                    date_last = i['date_last']
                if 'md5' in i:
                    md5 = i['md5']
                if 'url' in i:
                    url = i['url']
                if 'country' in i:
                    country = i['country']

                data = {
                    'domain': domain,
                    'type': itype,
                    'confidence': confidence,
                    'severity': severity,
                    'source': source,
                    'last seen': date_last,
                    'md5 hash': md5,
                    'url': url,
                    'country': country
                }
                self._add_result("IP Reputation", str(ip), data)
    def domain_intelligence(self, domain, config):

        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        url = config['url']
        api = config['apiKey']
        user= config['user_email']

        self._info("Domain  : "+ str(domain))
        domain_check = url + '/intelligence/?username=' + user + '&ip=' + '&api_key=' + api +'&value__exact='+str(domain) + '&limit=25'

        r = requests.get(domain_check, headers={'ACCEPT': 'application/json'}, verify=True, proxies=proxies)

        if r.status_code != 200:
            self._error("Response code not 200.")
            return
        data = {}
        self._info("Status : %s" % r.status_code)
        self._info("JSON : %s" % r.json())
        results = r.json()
        objects = results['objects']

        type = 'N/A'
        ip = 'N/A'
        org = 'N/A'
        threat = 'N/A'
        confidence = 'N/A'
        score = 'N/A'
        source = 'N/A'
        status = 'N/A'
        modified_ts = 'N/A'
        for i in objects:
            if 'itype' in i:
                type = i['itype']
            if 'ip' in i:
                ip = i['ip']
            if 'org' in i:
                org = i['org']
            if 'threat_type' in i:
                threat = i['threat_type']
            if 'confidence' in i:
                confidence = i['confidence']
            if 'threatscore' in i:
                score = i['threatscore']
            if 'source' in i:
                source = i['source']
            if 'status' in i:
                status = i['status']
            if 'modified_ts' in i:
                modified_ts = i['modified_ts']

            data = {
                'type': type,
                'ip': ip,
                'org': org,
                'threat': threat,
                'confidence': confidence,
                'threatscore': score,
                'source': source,
                'status': status,
                'modified_ts': modified_ts
            }
            self._add_result("IP Reputation", str(domain), data)

    def run(self, obj, config):


        if obj._meta['crits_type'] == 'IP':
            self.ip_intelligence(obj.ip, config)
        if obj._meta['crits_type'] == 'Domain':
            self.domain_intelligence(obj.domain,config)
        if obj._meta['crits_type'] == "Indicator":
            match_ip = re.match("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$", str(obj.indicator))
            if match_ip.group(0):
                self.ip_intelligence(obj.value,config)
            else:
                match_domain= re.match("^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", str(obj.value))

                if match_domain is None:
                    return
                elif match_domain.group(0):
                    self.domain_intelligence(obj.value,config)
                else:
                    self._add_result("NO MATCHING INDICATOR")

