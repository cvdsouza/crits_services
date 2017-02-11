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
            if 'context' in subdict:
                data ={
                    "Source": subdict['source'],
                    "Context": subdict['context'],
                    "Last Seen" : subdict['last_seen']
                }
                self._add_result("IP Context", mkey, data)

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

        '''
        Check if Indicator is IPv4
        '''
        if socket.inet_aton(str(obj.value)):
            self._info("IPv4 Address : "+str(obj.value))
            self.iprep_check(obj.value, config)
        else:
            pcre_url_check=''
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



    def _get_query_type(self, obj):
        """Abstract the query type from the call."""
        if obj._meta['crits_type'] == 'Domain':
            query = obj.domain
        elif obj._meta['crits_type'] == 'IP':
            query = obj.ip
        elif obj._meta['crits_type'] == 'Indicator':
            query = obj.value
        elif obj._meta['crits_type'] == 'Email':
            query = list()
            for field in ['sender', 'to', 'from_address']:
                tmp = getattr(obj, field)
                self._info("Values: %s " % str(tmp))
                if not tmp or tmp == '':
                    continue
                query.append(tmp)
        self._info("Query value passed along: %s." % str(query))
        return query

    def check_my_dump(self,obj,config):
        query = self._get_query_type(obj)
        field ='email'
        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        url = config['url_dump']
        api = config['apiKey']

        if type(query)==list:
            for item in query:
                if type(item) == list:
                    for email in item:

                        checkmydump = url + 'api/email/' + email + '?apikey=' + api
                        self._info("Email addresses in list of list : %s" %item)
                        r = requests.get(checkmydump, verify=False, proxies=proxies)
                        if r.status_code != 200:
                            self._error("Response code not 200")
                            return
                        results = r.json()
                        self._info("CMD returned inside list of list : %s" % results)
                        if 'message' in results:
                            self._add_result("Check My Dump", results['message'])
                        else:

                            for record in results['rows']:
                                data = {'Username': record.get['username'],
                                        'Domain': record['domain'],
                                        'Password': record['password'],
                                        'Userbase': record['userbase'],
                                        }
                                self._add_result("Check My Dump", str(item), data)
                else:
                    checkmydump = url + 'api/email/' + str(item) + '?apikey=' + api
                    self._info("Email addresses : %s" % item)
                    r = requests.get(checkmydump, verify=False, proxies=proxies)
                    if r.status_code != 200:
                        self._error("Response code not 200")
                        return

                    results = r.json()
                    self._info("CMD returned : %s" %results)
                    if 'message' in results:
                       self._add_result("Check My Dump" , results['message'])
                    else:

                        for record in results['rows'][0]:
                            data = {'Username' : record.get['username'],
                                    'Domain': record['domain'],
                                    'Password': record['password'],
                                    'Userbase': record['userbase'],
                                    }
                            self._add_result("Check My Dump", str(item), data)
        else:
            checkmydump = url + 'api/email/' + query + '?apikey=' + api
            r = requests.get(checkmydump, verify=False, proxies=proxies)
            if r.status_code != 200:
                self._error("Response code not 200")
                return

            results = r.json()
            if 'message' in results:
                self._add_result("Check My Dump", results['message'])
            else:

                for record in results['rows']:
                    data = {'Username': record.get['username'],
                            'Domain': record['domain'],
                            'Password': record['password'],
                            'Userbase': record['userbase'],
                            }
                    self._add_result("Check My Dump", record['username'], data)


    def run(self, obj, config):

        if obj._meta['crits_type'] == 'IP':
            self.iprep_check(obj.ip, config)
        elif obj._meta['crits_type'] == 'Indicator':
            self.pcre_match(obj,config)
        #elif obj._meta['crits_type'] == 'Email':
            #self.check_my_dump(obj,config)



