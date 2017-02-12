import logging
import json
import requests

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms
from django.conf import settings

logger = logging.getLogger(__name__)

class OpenDNSService(Service):
    """
    Request more information about an artifacts from OpenDNS
    """

    name = "opendns_investigate"
    version = '1.0.0'
    template = "opendns_service_template.html"
    supported_types = [ 'Domain', 'IP' ]
    description = "Lookup domains and IPs in OpenDNS."

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.OpenDNSConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def parse_config(config):
        if not config['Investigate_API_Token']:
            raise ServiceConfigError("API token required.")

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.OpenDNSConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.OpenDNSConfigForm(initial=config),
                                 'config_error': None})
        form = forms.OpenDNSConfigForm
        return form, html

    @staticmethod
    def save_runtime_config(config):
        del config['Investigate_API_Token']

    def _replace(self, string):
        return string.replace("_", " ")

    @property
    def proxies(self):
        proxy_host = self.config.get('proxy_host')
        proxy_port = self.config.get('proxy_port')
        if proxy_host:
            proxy = proxy_host + ':' + str(proxy_port)
        else:
            proxy = ''
        return {'http': proxy, 'https': proxy}

    def run(self, obj, config):

        '''

        Adding Proxy Configurations
        '''
        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        token = config.get('Investigate_API_Token', '')
        uri = config.get('Investigate_URI', '')
        headers = {'Authorization': 'Bearer ' + token}
        reqs = {}
        resps = {}
        #scores = {u'-1': 'Bad', u'0': 'Unknown', u'1': 'Good'}
        scores = {-1: 'Bad', 0: 'Unknown', 1: 'Good'}
        rir = {1 : 'AfriNIC: Africa', 2: 'APNIC: Asia, Australia, New Zealand, and neighboring countries', 3: 'ARIN: United States, Canada, several parts of the Caribbean region, and Antarctica.', 4: 'LACNIC: Latin America and parts of the Caribbean region', 5:'RIPE NCC: Europe, Russia, the Middle East, and Central Asia', 0:'Unknown / Not Available'}

        if not token:
            self._error("A valid API token is required to use this service.")

        if obj._meta['crits_type'] == 'Domain':
            thing = obj.domain
            reqs["categorization"] = "/domains/categorization/" + thing + "?showLabels"
            #reqs["score"] = "/domains/score/" + thing
            reqs["recommendations"] = "/recommendations/name/" + thing + ".json"
            reqs["links"] = "/links/name/" + thing + ".json"
            reqs["security"] = "/security/name/" + thing + ".json"
            reqs["latest_tags"] = "/domains/" + thing + "/latest_tags"
            reqs["dnsdb"] = "/dnsdb/name/a/" + thing + ".json"
        elif obj._meta['crits_type'] == 'IP':
            thing = obj.ip
            reqs["dnsdb"] = "/dnsdb/ip/a/" + thing + ".json"
            reqs["latest_domains"] = "/ips/" + thing + "/latest_domains"
            reqs['bgp_routes']="/bgp_routes/ip/"+thing+"/as_for_ip.json"
        else:
            logger.error("Unsupported type.")
            self._error("Unsupported type.")
            return

        try:
            for r in reqs.keys():
                resp = requests.get(uri + reqs[r], headers=headers, proxies=proxies)

                if resp.status_code == 204:
                    logger.error("No content status returned from request: %s" % (r))
                    self._error("No content status returned from request: %s" % (r))
                    resps[r] = "No content status returned from request: %s" % (r)
                elif resp.status_code != 200:
                    logger.error("Request: %s, error, %s" % (r, resp.reason))
                    self._error("Request: %s, error, %s" % (r, resp.reason))
                    resps[r] = "Request: %s, error, %s" % (r, resp.reason)
                else:
                    resps[r] = json.loads(self._replace(resp.content))

        except Exception as e:
            logger.error("Network connection or HTTP request error (%s)" % e)
            self._error("Network connection or HTTP request error (%s)" % e)
            return

        for r in resps.keys():
            if r == 'categorization':
                self._add_result(r, thing, resps[r][thing])
                self._add_result('Score', thing, {'Score': scores[resps[r][thing]['status']]})
            elif r == 'dnsdb':
                self._add_result(r, thing, resps[r]['features'])
            elif r == 'security':
                self._add_result(r, thing, resps[r])
            elif r == 'latest_tags':
                for tag in resps[r]:
                    self._add_result(r, thing, tag)
            elif r == 'recommendations':
                self._add_result(r, thing, resps[r])
            elif r == 'links':
                self._add_result(r, thing, resps[r])
            elif r == 'latest_domains':
                for domain in resps[r]:
                    self._add_result(r, domain['name'], domain)
            elif r =='bgp_routes':
                for i in resps[r]:
                    self._add_result(r,thing,i)
            else:
                self._add_result(r, thing, {str(type(resps[r])): str(resps[r])})
                logger.error("Unsure how to handle %s" % (str(resps[r])))
                self._error("Unsure how to handle %s" % (str(resps[r])))
