import requests
import re
import logging


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
    supported_types = ['Sample','IP','Indicator']
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
            ip_check = url+'iprep.php/'+'/intelligence/?username=' + user +'&ip='+str(ip)+ '&api_key=' + api + '&limit=25'

            r = requests.get(ip_check,verify=False, proxies= proxies)

            if r.status_code != 200:
                self._error("Response code not 200.")
                return
            data = {}
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
                if i['domain']:
                    domain = i['domain']
                if i['itype']:
                    itype = i['itype']
                if i['confidence']:
                    confidence = i['confidence']
                if i['severity']:
                    severity = i['severity']
                if i['source']:
                    source = i['source']
                if i['date_last']:
                    date_last = i['date_last']
                if i['md5']:
                    md5 = i['md5']
                if i['url']:
                    url = i['url']
                if i['country']:
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

    def run(self, obj, config):

        if obj._meta['crits_type'] == 'IP':
            self.ip_intelligence(obj.ip, config)