import logging
import requests
import pythonwhois
import re

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from crits.indicators.indicator import Indicator
from . import forms
from . import dtapi

logger = logging.getLogger(__name__)

class WHOISService(Service):
    """
    Request more information about an artifacts from WHOIS or pyDat.
    """

    name = "whois"
    version = '1.0.0'
    supported_types = [ 'Domain', 'Indicator', 'IP' ]
    template = 'whois_service_template.html'
    description = "Lookup WHOIS records for domains."

    @staticmethod
    def parse_config(config):
        # Must have both DT API key and DT Username or neither.
        if ((config['dt_api_key'] and not config['dt_username']) or
           (config['dt_username'] and not config['dt_api_key'])):
            raise ServiceConfigError("Must specify both DT API and username.")

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.WHOISConfigForm().fields
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
        fields = forms.WHOISConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.WHOISConfigForm(initial=config),
                                 'config_error': None})
        form = forms.WHOISConfigForm
        return form, html

    @staticmethod
    def save_runtime_config(config):
        if config['dt_api_key']:
            del config['dt_api_key']
        if config['dt_username']:
            del config['dt_username']

    @staticmethod
    def bind_runtime_form(analyst, config):
        if 'live_query' not in config:
            config['live_query'] = False
        if 'pydat_query' not in config:
            config['pydat_query'] = False
        if 'dt_query' not in config:
            config['dt_query'] = False
        form = forms.WHOISRunForm(pydat_url=config['pydat_url'],
                                  dt_api_key=config['dt_api_key'],
                                  data=config)
        return form

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        html = render_to_string("services_run_form.html",
                                {'name': self.name,
                                 'form': forms.WHOISRunForm(pydat_url=config['pydat_url'],
                                                            dt_api_key=config['dt_api_key']),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html



    # Live queries work well on the "bigger" TLDs. Using it on a .coop
    # results in hilarity because the parser misses everything.
    # This is a tough nut to crack.
    def do_live_query(self, obj, config):
        try:
            results = pythonwhois.get_whois(obj.domain)
        except pythonwhois.shared.WhoisException as e:
            self._error("Unable to find WHOIS information. %s" % str(e))
            return

        contacts = results.get('contacts', {})
        for contact_type in contacts.keys():
            # If not provided it defaults to None.
            if not contacts[contact_type]:
                continue
            for k, v in contacts[contact_type].iteritems():
                self._add_result("Live: " + contact_type + " Contact", v, {'Key': k})

        for ns in results.get('nameservers', []):
            self._add_result('Live: Nameservers', ns, {'Key': 'Nameserver'})

        for registrar in results.get('registrar', []):
            self._add_result('Live: Registrar', registrar, {'Key': 'Registrar'})

        for key in ['creation_date', 'expiration_date', 'updated_date']:
            for date in results.get(key, []):
                if date:
                    self._add_result('Live: Dates', date, {'Key': key})

    def do_pydat_query(self, obj, config):

        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        # Check for trailing slash, because pydat.example.org//ajax is bad.
        base = config['pydat_url']
        if base[-1] != '/':
            base += '/'

        # Figure out how many versions exist
        url = base + 'ajax/domain/' + obj.domain + '/'

        r = requests.get(url, proxies=proxies)
        if r.status_code != 200:
            self._error("Response code not 200.")
            return

        results = r.json()
        if not results['success']:
            self._error(results['error'])
            return

        if results['total'] == 0:
            self._info("Metadata not found in pyDat")
            return

        link = base + 'domains/domainName/' + obj.domain
        self._info('pyDat URL: %s' % link)

        # Collect available versions and present them in the log. The list
        # will be sorted and the highest value will be used to fetch the
        # "latest" results.
        versions = []
        for data in results['data']:
            try:
                versions.append(data['Version'])
                versions_check = data['Version']
            except KeyError:
                versions.append(data['dataVersion'])
                versions_check = data['dataVersion']

            self._info('Version found: %s' % versions_check)

        versions.sort()
        latest = versions[-1]

        for data in results['data']:
            # Only grab the most recent version.
            if versions_check != latest:
                continue
            for k, v in data.iteritems():
                # Don't add empty strings.
                if v:
                    self._add_result('pyDat Latest', v, {'Key': k})

    def do_dt_query(self, obj, config):

        dt = dtapi.dtapi(config['dt_username'], config['dt_api_key'])
        try:
            resp=""
            resp1=""
            resp2=""
            resp3=""
            if obj._meta['crits_type'] == 'Domain':
                resp = dt.whois_parsed(obj.domain)
                resp1 = dt.reverse_ns(obj.domain,'80')
                resp2 = dt.reverse_ip(obj.domain,'80')
                resp3 = dt.hosting_history(obj.domain)
            elif  obj._meta['crits_type'] == 'IP':
                self._info("IP Selected %s" % str(obj.ip))
                resp = dt.whois_parsed(obj.ip)
                resp1 = dt.reverse_ns(obj.ip, '80')
                resp2 = dt.reverse_ip(obj.ip, '80')
                resp3 = dt.hosting_history(obj.ip)


        except dtapi.DTError as e:
            self._info(str(e))
            return

        results = resp.json()
        results = results['response']['parsed_whois']
        results1 = resp1.json()
        results1 = results1['response']['primary_domains']
        results2 = resp2.json()
        results2 = results2['response']['ip_addresses']
        results3 = resp3.json()
        results3 = results3['response']

        contacts = results.get('contacts', {})
        for contact_type in contacts.keys():
            for k, v in contacts[contact_type].iteritems():
                if v:
                    self._add_result("DomainTools: " + contact_type + " Contact", v, {'Key': k})

        for key in ['created_date', 'expired_date', 'updated_date']:
            if results[key]:
                self._add_result('DomainTools: Dates', results[key], {'Key': key})

        for ns in results.get('nameservers', []):
            self._add_result('DomainTools: Nameservers', ns, {})

        registrar = results.get('registrar', {})
        for k, v in registrar.iteritems():
            if v:
                self._add_result('DomainTools: Registrar', v, {'Key': k})

        for pd in results1:
            self._add_result('DomainTools: Name Server Domains',pd)

        for reverseIP in results2.get('domain_names'):
            self._add_result('DomainTools: Reverse IP', reverseIP)


    def dt_ip_history(self, obj, config):
        dt = dtapi.dtapi(config['dt_username'], config['dt_api_key'])

        try:
            resp3 = dt.hosting_history(obj.domain)

        except dtapi.DTError as e:
            self._info(str(e))
            return

        results3 = resp3.json()
        results3 = results3['response']

        '''
            Adding IP History
            '''
        ipHistory = results3.get('ip_history')

        for info in ipHistory:
            data = {
                'domain': info.get('domain'),
                'post_ip': info.get('post_ip'),
                'pre_ip': info.get('pre_ip'),
                'action': info.get('action'),
                'action date': info.get('actiondate'),
                'action in words': info.get('action_in_words'),
            }
            self._add_result('DomainTools: IP History' , data)

    def dt_registrar_history(self, obj, config):
        dt = dtapi.dtapi(config['dt_username'], config['dt_api_key'])

        try:
            resp3 = dt.hosting_history(obj.domain)

        except dtapi.DTError as e:
            self._info(str(e))
            return

        results3 = resp3.json()
        results3 = results3['response']

        '''
            Adding IP History
            '''
        ipHistory = results3.get('registrar_history')

        for info in ipHistory:
            data = {
                'domain': info.get('domain'),
                'date_updated': info.get('date_updated'),
                'date_created': info.get('date_created'),
                'date_expires': info.get('date_expires'),
                'date_lastchecked': info.get('date_lastchecked'),
                'registrar': info.get('registrar'),
                'registrartag': info.get('registrartag'),
            }
            self._add_result('DomainTools: Registrar History', data)

    def dt_nameserver_history(self, obj, config):
        dt = dtapi.dtapi(config['dt_username'], config['dt_api_key'])

        try:
            resp3 = dt.hosting_history(obj.domain)

        except dtapi.DTError as e:
            self._info(str(e))
            return

        results3 = resp3.json()
        results3 = results3['response']

        '''
            Adding IP History
        '''
        ipHistory = results3.get('nameserver_history')

        for info in ipHistory:
            data = {
                'domain': info.get('domain'),
                'action': info.get('action'),
                'actiondate': info.get('actiondate'),
                'action_in_words': info.get('action_in_words'),
                'post_mns': info.get('post_mns'),
                'pre_mns': info.get('pre_mns'),
            }
            self._add_result('DomainTools: Nameserver History', data)

    def dt_indicator_parser(self,obj,config):
        # DomainTools on IP Indicators
        # Validate IP Indicator
        valid_types = ('Domain','IPv4 Address')

        match_ip = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", str(obj.value))
        if match_ip:
            self._info("IPv4 Address : " + str(obj.value))
            self.do_dt_query(obj, config)
            self.dt_ip_history(obj,config)
            self.dt_registrar_history(obj, config)
            self.dt_nameserver_history(obj, config)

    def run(self, obj, config):
        if settings.HTTP_PROXY:
            self.proxies = {'http': settings.HTTP_PROXY,
                            'https': settings.HTTP_PROXY}
        else:
            self.proxies = {}

        if config['live_query']:
            self.do_live_query(obj, config)

        if config['pydat_url'] and config['pydat_query']:
            self.do_pydat_query(obj, config)

        if config['dt_api_key'] and config['dt_username'] and config['dt_query'] and obj._meta['crits_type'] == 'Domain':
            self.do_dt_query(obj, config)
            self.dt_ip_history(obj, config)
            self.dt_registrar_history(obj, config)
            self.dt_nameserver_history(obj, config)

        if config['dt_api_key'] and config['dt_username'] and config['dt_query'] and obj._meta['crits_type'] == 'Indicator':
           self.dt_indicator_parser(obj,config)

        if config['dt_api_key'] and config['dt_username'] and config['dt_query'] and obj._meta['crits_type'] == 'IP':
            self.do_dt_query(obj, config)
            #self.dt_ip_history(obj, config)
            #self.dt_registrar_history(obj, config)
            #self.dt_nameserver_history(obj, config)