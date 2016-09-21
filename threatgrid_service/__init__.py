import urlparse
import logging
import requests
import json
import time

from django.template.loader import render_to_string
from django.conf import settings
from crits.services.core import Service, ServiceConfigError
from crits.indicators.indicator import Indicator
from crits.vocabulary.indicators import IndicatorTypes

from . import forms

logger = logging.getLogger(__name__)


class ThreatGRIDService(Service):
    """
    ThreatGRID interoperability with CRITS.

    Requires an API key from the specified ThreatGRID appliance.
    """

    name = 'threatgrid'
    version = '1.0.1'
    supported_types = ['Sample']
    template = 'tg_service_template.html'
    description = 'Submit a sample to ThreatGRID'

    host = ''
    api_key = ''
    md5 = ''

    @staticmethod
    def save_runtime_config(config):
        del config['api_key']

    @staticmethod
    def parse_config(config):
        if not config['api_key']:
            raise ServiceConfigError('API key required.')

    @staticmethod
    def get_config(existing_config):
        """
        Retrieve configuration information for ThreatGRID
        """
        config = {}
        fields = forms.ThreatGRIDConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @classmethod
    def generate_config_form(self, config):
        """
        Provide the configuration information for ThreatGRID
        """
        # Convert sigfiles to newline separated strings
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.ThreatGRIDConfigForm(initial=config),
                                 'config_error': None})
        form = forms.ThreatGRIDConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        """
        Get configuration information from service settings
        """
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.ThreatGRIDConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    @staticmethod
    def bind_runtime_form(analyst, config):
        """
        Set service runtime information
        """
        if 'submit' not in config:
            if 'auto_submit' not in config:
                config['submit'] = False
            else:
                config['submit'] = config['auto_submit']
        return forms.ThreatGRIDRunForm(config)

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        """
        Allow user to determine if they want to submit a sample for analysis
        """
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.ThreatGRIDRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    def api_request(self, path, req_params, req_type='get'):
        """
        Handle HTTP/HTTPS requests to the API
        - Implement error handling in a single location
        """
        url = urlparse.urljoin(self.host, path)
        req_params['api_key'] = self.api_key
        req_verify = False  # SSL CERT verification

        if settings.HTTP_PROXY:
            proxies = {'http': settings.HTTP_PROXY,
                       'https': settings.HTTP_PROXY}
        else:
            proxies = {}

        if req_type == 'get':
            response = requests.get(url, params=req_params, verify=req_verify,proxies=proxies)
            # Response handling
            if response.status_code == 200:
                # Success
                result = json.loads(response.content)
                return result
            else:
                # Error reporting
                error = json.loads(response.content)
                for item in error.get('error').get('errors'):
                    code = item.get('code')
                    message = item.get('message')
                    self._info('HTTP Response {}: {}'.format(code, message))
                return
        elif req_type == 'post':
            if 'sample' in req_params:
                # Submit attached samples
                data = req_params.pop('sample')
                response = requests.post(url,
                                         params=req_params,
                                         files={'sample': (req_params.get('filename'), data)},
                                         verify=req_verify, proxies=proxies)
            else:
                response = requests.post(url,
                                         params=req_params,
                                         verify=req_verify, proxies=proxies)
            # Response handling
            if response.status_code == 200:
                # Success
                result = json.loads(response.content)
                return result
            else:
                # Error reporting
                error = json.loads(response.content)
                for item in error.get('error').get('errors'):
                    code = item.get('code')
                    message = item.get('message')
                    self._info('HTTP Response {}: {}'.format(code, message))
                return
        return

    def sample_search(self, params):
        """
        Search for results using provided parameter(s)
        - Only 1 page of results are displayed.
        """

        # Set API query parameters and conduct query
        recent_id = 0
        response = self.api_request('/api/v2/samples', params, 'get')
        if response:
            result_count = response.get('data', {}).get('current_item_count', 0)
            if result_count > 0:
                # Handle search by ID
                if 'id' in params.keys():
                    item = response.get('data', {}).get('items')
                    if len(item) == 1:
                        # Detect analysis state
                        state = item[0].get('state', '')
                        if state in ['pending', 'running', 'proc', 'wait', 'prep']:
                            return
                        elif state in ['job_done', 'succ']:
                            url = 'https://panacea.threatgrid.com/samples/'+item[0].get('filename', '')
                            result = {
                                    'id':               item[0].get('id'),
                                    'submitted_at':     item[0].get('submitted_at'),
                                    'tags':             ''.join(item[0].get('tags', [])),
                                    'login':            item[0].get('login'),
                                    'state':            item[0].get('state'),
                                    'status':           item[0].get('status'),
                                    'ThreatGrid Sample Access': url,
                                    }
                            self._add_result('threatgrid_job', item[0].get('filename', ''), result)
                            self._notify()
                            return item[0].get('id')
                        elif state == 'fail':
                            result = {
                                    'id':               item[0].get('id'),
                                    'submitted_at':     item[0].get('submitted_at'),
                                    'tags':             ''.join(item[0].get('tags', [])),
                                    'login':            item[0].get('login'),
                                    'state':            item[0].get('state'),
                                    'status':           item[0].get('status'),
                                    }
                            self._add_result('threatgrid_job', 'Failed', result)
                            self._notify()
                            self._info('ThreatGRID analysis failed ({}).'.format(item[0].get('status', '')))
                            return -1
                        else:
                            self._info('ThreatGRID returned unknown state type ({}).'.format(item[0].get('state', '')))
                            return
                    else:
                        self._error('ThreatGRID returned unexpeced number of results for the sample ID.')
                else:
                    # Handle other search types (MD5 etc.)
                    for item in response.get('data', {}).get('items'):
                        result = {
                                'id':               item.get('id'),
                                'submitted_at':     item.get('submitted_at'),
                                'tags':             ''.join(item.get('tags', [])),
                                'login':            item.get('login'),
                                'state':            item.get('state'),
                                'status':           item.get('status'),
                                }
                        self._add_result('threatgrid_job', item.get('filename', ''), result)
                        recent_id = item.get('id')
                    self._notify()
                    self._info('{} results returned from ThreatGRID search.'.format(result_count))
                    # Return one of the analysis IDs (used to show further results)
                    return recent_id
        else:
            self._error('An error occured while looking for sample.')
        return

    def sort_iocs(self, iocs):
        """
        Sort IOCs by severity, confidence
        """
        for item in sorted(iocs, key=lambda x: (x.get('severity', 0), x.get('confidence', 0)), reverse=True):
            yield item
        return

    def sample_iocs(self, tg_id):
        """
        Get Sample IOCs for a given ThreatGRID id
        """
        url = '/api/v2/samples/' + tg_id + '/analysis/iocs'
        response = self.api_request(url, {}, 'get')
        if response:
            if response.get('data'):
                iocs = response.get('data', {}).get('items')
                for item in self.sort_iocs(iocs):
                    result = {
                            'hits':         item.get('hits'),
                            'severity':     item.get('severity'),
                            'confidence':   item.get('confidence'),
                            'categories':   ', '.join(item.get('category', [])),
                            }

                    self._add_result('threatgrid_ioc', item.get('title', ''), result)
                self._notify()
            elif response.get('error'):
                self._info('No IOCs were found for ThreatGRID id:{}'.format(tg_id))
            else:
                self._error('An error occured when attempting to get IOCs for id:{}'.format(tg_id))

    def sample_network(self, tg_id):
        """
        Get Sample Network indicators for a given ThreatGRID id
        """
        indicators = []
        url = '/api/v2/samples/' + tg_id + '/analysis/network_streams'
        response = self.api_request(url, {}, 'get')
        if response:
            if response.get('data'):
                # DNS
                for num in response.get('data', {}).get('items'):
                    item = response['data']['items'][num]
                    if item.get('protocol') == 'DNS':
                        # Process DNS lookups
                        dns_objects = item.get('decoded')
                        for obj in dns_objects:
                            result = {
                                'dns_query':    dns_objects[obj].get('query', {}).get('query_data'),
                                'dns_type':     dns_objects[obj].get('query', {}).get('query_type'),
                                }
                            dns_qid = dns_objects[obj].get('query', {}).get('query_id')
                            # Find the answer for each DNS query by id, type
                            for answer in dns_objects[obj].get('answers', []):
                                if answer.get('answer_id', 0) == dns_qid:
                                    if answer.get('answer_type', '') == result['dns_type']:
                                        result['dns_answer'] = answer.get('answer_data')
                                        break
                            indicators.append([result.get('dns_query'), IndicatorTypes.DOMAIN])
                            indicators.append([result.get('dns_answer'), IndicatorTypes.IPV4_ADDRESS])
                            self._add_result('threatgrid_dns'.format(tg_id), result.pop('dns_query'), result)
                self._notify()
                # HTTP
                for num in response.get('data', {}).get('items'):
                    item = response['data']['items'][num]
                    if item.get('protocol') == 'HTTP':
                        for decode in item.get('decoded'):
                            for entry in decode:
                                # Only show HTTP requests
                                if entry.get('type') == 'request':
                                    result = {
                                        'host':         entry.get('host'),
                                        'method':       entry.get('method'),
                                        'url':          entry.get('url'),
                                        'ua':           entry.get('headers', {}).get('user-agent'),
                                        'referer':      entry.get('headers', {}).get('referer'),
                                        'dst':          item.get('dst'),
                                        'dst_port':     item.get('dst_port'),
                                        }
                                    indicators.append([result.get('host'), IndicatorTypes.DOMAIN])
                                    indicators.append([result.get('dst'), IndicatorTypes.IPV4_ADDRESS])
                                    self._add_result('threatgrid_http'.format(tg_id), result.pop('host'), result)
                self._notify()
                # IP/Other
                for num in response.get('data', {}).get('items'):
                    item = response['data']['items'][num]
                    if item.get('protocol') == None:
                        result = {
                                'transport':    item.get('transport'),
                                'src':          item.get('src'),
                                'src_port':     item.get('src_port'),
                                'dst':          item.get('dst'),
                                'dst_port':     item.get('dst_port'),
                                'bytes':        item.get('bytes'),
                                'packets':      item.get('packets'),
                                }
                        indicators.append([result.get('dst'), IndicatorTypes.IPV4_ADDRESS])
                        self._add_result('threatgrid_ip'.format(tg_id), result.pop('transport'), result)
                self._notify()

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
                            self._add_result('add_threatgrid_indicators', indicator, tdict)

    def sample_submit(self, filename, crits_id, data):
        """
        Submit a sample to ThreatGRID
        """
        # Set API query parameters and submit sample
        params = {'tags': 'CRITS',
                  'filename': filename,
                  'os': '',
                  'osver': '',
                  'source': 'CRITS:{}'.format(crits_id),
                  'sample': data}
        response = self.api_request('/api/v2/samples', params, 'post')

        if response:
            self._info("Sample submitted to ThreatGRID (run time is 5 mins).")
            if response.get('data'):
                submitted = response.get('data')
                result = {
                        'id':               submitted.get('id'),
                        'submitted_at':     submitted.get('submitted_at'),
                        'tags':             ''.join(submitted.get('tags', [])),
                        'submission_id':    submitted.get('submission_id'),
                        'state':            submitted.get('state'),
                        'status':           submitted.get('status'),
                        }
                self._add_result('threatgrid_submitted', submitted.get('filename'), result)
                self._notify()
                if not self.md5 == submitted.get('md5').lower():
                    self._error("MD5 mismatch between ThreatGRID and CRITS.")
                return submitted.get('id')
        self._error("ThreatGRID sample submission failed.")
        return

    def run(self, obj, config):
        """
        Begin ThreatGRID service
        """
        self.host = config.get('host', '')
        self.api_key = config.get('api_key', '')
        self.md5 = obj.md5
        delay = 60
        count = 0
        max_delays = 8

        if obj._meta['crits_type'] == 'Sample':
            # Search for existing results or submit the sample
            found = self.sample_search({'md5': self.md5})
            if found:
                self._info('Showing details for ThreatGRID id {}'.format(found))
                self.sample_iocs(found)
                self.sample_network(found)
                # self.sample_processes_registry_keys_read(found)
                self.sample_processes(found)
            else:
                if config.get('submit'):
                    # Submit the sample
                    data = obj.filedata.read()
                    sample_id = self.sample_submit(obj.filename, obj.id, data)
                    # Wait for results (default analysis time is 5 mins)
                    if sample_id:
                        time.sleep(5)
                        found = self.sample_search({'id': sample_id})
                        while count <= max_delays and not found:
                            time.sleep(delay)
                            count += 1
                            found = self.sample_search({'id': sample_id})
                        # Render results
                        if found:
                            if found > 0:
                                self._info('Showing details for ThreatGRID id {}'.format(found))
                                self.sample_iocs(found)
                                self.sample_network(found)
                                # self.sample_processes_registry_keys_read(found)
                                self.sample_processes(found)
                                self._notify()
                        else:
                            self._error('ThreatGRID did not complete before timeout.')
                    else:
                        self._error('ThreatGRID sample submission did not return a valid id.')
                else:
                    self._info('Sample not found in ThreatGRID.')
        else:
            self._error("Invalid type passed to ThreatGRID service plugin.")

    def sample_processes(self, tg_id):

        self.sample_processes_overview(tg_id)
        self.sample_processes_files_activity(tg_id)

        self.sample_processes_startup_info(tg_id)

        self.sample_processes_registry_details_read(tg_id)

        self.sample_processes_registry_details_opened(tg_id)

        self.sample_processes_registry_details_created(tg_id)

        self.sample_processes_registry_details_deleted(tg_id)

        self.sample_processes_registry_details_modified(tg_id)


    def sample_processes_overview(self, tg_id):
            """
                Get Sample Processes Registry Keys Read for a given ThreatGRID id
                """
            response = self.sample_processes_response_return(tg_id)

            if response:
                if response.get('data'):
                    '''
                    Get Process Information from ThreatGrid
                    '''
                    for num in response.get('data', {}).get('items'):

                        item = response['data']['items'][num]


                        result1 = {}
                        if 'children' in item:
                            if item['children']:

                                for i in item['children']:
                                    result1 = i

                                data = {
                                    "PID": item.get('pid'),
                                    "Children" : result1,
                                    "Analysis Reason": item.get('analyzed_because')
                                }

                                self._add_result('ThreatGrid Process Results', item.get('process_name', ''), data)
                                self._notify()
                elif response.get('error'):
                    self._info('No processes were found for ThreatGRID id:{}'.format(tg_id))
                else:
                    self._error('An error occured when attempting to get processes for id:{}'.format(tg_id))

    def sample_processes_files_activity(self, tg_id):
        """
            Get Sample Processes file activity for a given ThreatGRID id
            """
        nl = '\n'
        response = self.sample_processes_response_return(tg_id)
        if response:
            if response.get('data'):
                for num in response.get('data', {}).get('items'):

                    item = response['data']['items'][num]

                    filesChecked = {}
                    if 'files_checked' in item or \
                                    'files_deleted' in item or \
                                    'files_modified' in item or \
                                    'files_created' in item or \
                                    'files_read' in item :
                        for i in item['files_checked']:
                            filesChecked = i

                        filesDeleted = {}
                        for i in item['files_deleted']:
                            filesDeleted = i

                        filesModified = {}
                        for i in item['files_modified']:
                            filesModified = i

                        filesCreated = {}
                        for i in item['files_created']:
                            filesCreated = i

                        filesRead = {}
                        for i in item['files_read']:
                            filesRead = i

                        if (item.get('files_modified') or item.get('files_created')):
                            registry_actions = 'True'
                        else:
                            registry_actions = 'False'

                        data = {
                            "PID" : item.get('pid'),
                            "File Actions Observed": registry_actions,
                            "Files Checked" : filesChecked,
                            "Files Deleted" :filesDeleted ,
                            "Files Modified" : filesModified ,
                            "Files Created" : filesCreated,
                            "Files Read" : filesRead ,
                        }

                        self._add_result('ThreatGrid Process Files Activity', item.get('process_name', ''), data)
                        self._notify()
            elif response.get('error'):
                self._info('No processes were found for ThreatGRID id:{}'.format(tg_id))
            else:
                self._error('An error occured when attempting to get processes for id:{}'.format(tg_id))

    def sample_processes_registry_details(self, tg_id):
        """
            Get Sample Processes of Registry details for a given ThreatGRID id
            """
        nl = '\n'
        response = self.sample_processes_response_return( tg_id)
        if response:
            if response.get('data'):
                for num in response.get('data', {}).get('items'):
                    item = response['data']['items'][num]

                    registry_keys_read = {}
                    for i in item['registry_keys_read']:
                        registry_keys_read = i

                    registry_keys_opened = {}
                    for i in item['registry_keys_opened']:
                        registry_keys_opened = i

                    registry_keys_created = {}
                    for i in item['registry_keys_created']:
                        registry_keys_created = i

                    registry_keys_deleted = {}
                    for i in item['registry_keys_deleted']:
                        registry_keys_deleted = i

                    registry_keys_modified = {}
                    for i in item['registry_keys_modified']:
                        registry_keys_modified = i

                    data = {
                        "PID": item.get('pid'),
                        "Registry Keys Read" : registry_keys_read,
                        "Registry Keys Opened" : registry_keys_opened,
                        "Registry Keys Created" : registry_keys_created,
                        "Registry Keys Deleted" : registry_keys_deleted,
                        "Registry Keys Modified" : registry_keys_modified,
                    }
                    self._add_result('ThreatGrid Registry Keys Details', item.get('process_name', ''), data)
                    self._notify()
            elif response.get('error'):
                self._info('No processes were found for ThreatGRID id:{}'.format(tg_id))
            else:
                self._error('An error occured when attempting to get processes for id:{}'.format(tg_id))

    '''
    Process Startup Info.
    '''
    def sample_processes_startup_info(self, tg_id):
        """
            Get Sample Processes for a given ThreatGRID id
            """
        response = self.sample_processes_response_return(tg_id)
        if response:
            if response.get('data'):
                for num in response.get('data', {}).get('items'):
                    item = response['data']['items'][num]


                    dll_path = ""
                    command_line = ""
                    window_title = ""
                    current_directory = ""
                    image_pathname=""
                    if 'startup_info' in response['data']['items'][num]:

                        startup_info = response['data']['items'][num]['startup_info']
                        dll_path_list = {}
                        if 'dll_path' in startup_info:
                            dll_path = startup_info['dll_path']
                            dll_path_list = dll_path.split(';')

                        command_line_list = {}
                        if 'command_line' in startup_info:
                            command_line = startup_info['command_line']
                            command_line_list = command_line.split(';')

                        window_title_list = {}
                        if 'window_title' in startup_info:
                            window_title = startup_info['window_title']
                            window_title_list = window_title.split(';')

                        current_directory_list = {}
                        if 'current_directory' in startup_info:
                            current_directory = startup_info['current_directory']
                            current_directory_list = current_directory.split(';')

                        image_pathname_list = {}
                        if 'image_pathname' in startup_info:
                            image_pathname = startup_info['image_pathname']
                            image_pathname_list = image_pathname.split(';')

                        data = {
                            "dll path": dll_path,
                            "command line ": command_line,
                            "window title" : window_title,
                            "current directory": current_directory,
                            "image_pathname" : image_pathname,
                        }
                        self._add_result('ThreadGrid Process Startup Info', item.get('process_name', ''), data)
                        self._notify()
            elif response.get('error'):
                self._info('No processes were found for ThreatGRID id:{}'.format(tg_id))
            else:
                self._error('An error occured when attempting to get processes for id:{}'.format(tg_id))


    def sample_processes_response_return(self, tg_id):
        url = '/api/v2/samples/' + tg_id + '/analysis/processes'
        response = self.api_request(url, {}, 'get')
        return response

    '''
    Registry File Details
    '''
    def sample_processes_registry_details_read(self, tg_id):
        """
            Get Sample Processes of Registry details for a given ThreatGRID id
            """
        nl = '\n'
        response = self.sample_processes_response_return(tg_id)
        if response:
            if response.get('data'):
                for num in response.get('data', {}).get('items'):
                    item = response['data']['items'][num]

                    registry_keys_read_name = {}
                    registry_keys_read_value = {}
                    if 'registry_keys_read' in item:
                        for i in item['registry_keys_read']:
                            registry_keys_read_name = i['key_name']
                            registry_keys_read_value = i['key_value']
                        data={
                            'Key Value': registry_keys_read_value
                        }

                        self._add_result('ThreatGrid Registry Keys Read', registry_keys_read_name,data)
                        self._notify()
            elif response.get('error'):
                self._info('No processes were found for ThreatGRID id:{}'.format(tg_id))
            else:
                self._error('An error occured when attempting to get processes for id:{}'.format(tg_id))

    def sample_processes_registry_details_opened(self, tg_id):
        """
            Get Sample Processes of Registry details for a given ThreatGRID id
            """
        nl = '\n'
        response = self.sample_processes_response_return(tg_id)
        if response:
            if response.get('data'):
                for num in response.get('data', {}).get('items'):
                    item = response['data']['items'][num]

                    registry_keys_access = {}
                    files_modified = {}
                    if 'registry_keys_opened' in item:
                        for i in item['registry_keys_opened']:
                            registry_keys_access = i['name']
                            files_modified = i['access']
                        data = {
                            'Access': files_modified
                        }

                        self._add_result('ThreatGrid Registry Keys Opened', registry_keys_access, data)
                        self._notify()
            elif response.get('error'):
                self._info('No processes were found for ThreatGRID id:{}'.format(tg_id))
            else:
                self._error('An error occured when attempting to get processes for id:{}'.format(tg_id))

    def sample_processes_registry_details_created(self, tg_id):
        """
            Get Sample Processes of Registry details for a given ThreatGRID id
            """
        nl = '\n'
        response = self.sample_processes_response_return(tg_id)
        if response:
            if response.get('data'):
                for num in response.get('data', {}).get('items'):
                    item = response['data']['items'][num]

                    registry_keys_read_name = {}
                    registry_keys_read_value = {}
                    if 'registry_keys_created' in item:
                        for i in item['registry_keys_created']:
                            registry_keys_read_name = i['name']
                            registry_keys_read_value = i['access']
                        data = {
                            'Access': registry_keys_read_value
                        }

                        self._add_result('ThreatGrid Registry Keys Created', registry_keys_read_name)
                        self._notify()
            elif response.get('error'):
                self._info('No processes were found for ThreatGRID id:{}'.format(tg_id))
            else:
                self._error('An error occured when attempting to get processes for id:{}'.format(tg_id))


    def sample_processes_registry_details_deleted(self, tg_id):
        """
            Get Sample Processes of Registry details for a given ThreatGRID id
            """
        nl = '\n'
        response = self.sample_processes_response_return(tg_id)
        if response:
            if response.get('data'):
                for num in response.get('data', {}).get('items'):
                    item = response['data']['items'][num]

                    registry_keys_read_name = {}
                    if 'registry_keys_deleted' in item:
                        for i in item['registry_keys_deleted']:
                            registry_keys_read_name = i

                        self._add_result('ThreatGrid Registry Keys Deleted', registry_keys_read_name)
                        self._notify()
            elif response.get('error'):
                self._info('No processes were found for ThreatGRID id:{}'.format(tg_id))
            else:
                self._error('An error occured when attempting to get processes for id:{}'.format(tg_id))

    def sample_processes_registry_details_modified(self, tg_id):
        """
            Get Sample Processes of Registry details for a given ThreatGRID id
            """
        nl = '\n'
        response = self.sample_processes_response_return(tg_id)
        if response:
            if response.get('data'):
                for num in response.get('data', {}).get('items'):
                    item = response['data']['items'][num]

                    registry_keys_read_name = {}
                    registry_keys_read_value = {}
                    if 'registry_keys_modified' in item:
                        for i in item['registry_keys_modified']:
                            if(i['name']):
                                registry_keys_read_name = i['name']

                        self._add_result('ThreatGrid Registry Keys Modified', registry_keys_read_name)
                        self._notify()
            elif response.get('error'):
                self._info('No processes were found for ThreatGRID id:{}'.format(tg_id))
            else:
                self._error('An error occured when attempting to get processes for id:{}'.format(tg_id))