# File: zoom_connector.py
#
# Copyright (c) 2021-2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import json
from datetime import datetime, timedelta
from urllib.parse import unquote

import encryption_helper
import jwt
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from password_generator import PasswordGenerator
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from requests.auth import HTTPBasicAuth

from zoom_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ZoomConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ZoomConnector, self).__init__()

        self._state = None
        self._token = None
        self._base_url = None

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_msg = ERROR_MSG_UNAVAILABLE

        self.error_print("Error occurred.", e)

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception as e:
            self.error_print("Error occurred while fetching exception information. Details: {}".format(str(e)))

        if not error_code:
            error_text = "Error Message: {}".format(error_msg)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

        return error_text

    def _process_empty_response(self, response, action_result):

        if response.status_code in (200, 204):
            return RetVal(phantom.APP_SUCCESS, {})

        msg = 'Status code: {}. Empty response and no information in the header'.format(response.status_code)
        return RetVal(action_result.set_status(phantom.APP_ERROR, msg), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(['script', 'style', 'footer', 'nav']):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = 'Cannot parse error details'

        message = 'Status Code: {0}. Data from server:\n{1}\n'.format(status_code, unquote(error_text))

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Unable to parse JSON response. Error: {0}'.format(error_message), None))

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = 'Error from server. Status Code: {0} Data from server: {1}'.format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_jwt(self, config):
        payload = {
            'iss': self._api_key,
            'exp': datetime.now() + timedelta(hours=8)
        }

        token = jwt.encode(payload, self._api_secret)

        return token

    def _make_rest_call(self, endpoint, action_result, method='get', **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()
        if self._auth_method == "JWT" and (not self._api_key or not self._api_secret):
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Api key or Api secret not found"), None)

        if self._auth_method == "JWT":
            token = self._get_jwt(config)
            headers = {
                'Authorization': 'bearer {}'.format(token),
                'User-Agent': 'Zoom-Jwt-Request',
                'content-type': 'application/json'
            }
        else:
            headers = {
                'Authorization': 'Bearer {}'.format(self._token),
                'content-type': 'application/json',
            }

        kwargs['headers'] = headers

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            msg = 'Invalid method: {0}'.format(method)
            self.error_print(msg)
            return RetVal(action_result.set_status(phantom.APP_ERROR, msg), resp_json)

        # Create a URL to connect to
        url = '{}{}'.format(self._base_url, endpoint)

        try:
            r = request_func(
                            url,
                            timeout=DEFAULT_TIMEOUT,
                            **kwargs)
            if r.status_code != requests.codes.no_content and self._auth_method == SERVER_TO_SERVER_OAUTH_METHOD:
                resp_json = r.json()
                if resp_json.get('code') == 124 and (resp_json.get("message", "") in INVALID_TOKEN_MSG_LIST):
                    self._get_token(config)
                    kwargs['headers']['Authorization'] = 'Bearer {}'.format(self._token)
                    if not self._token:
                        return RetVal(action_result.set_status(phantom.APP_ERROR, 'Invalid token, please rerun the test connectivity'), r)
                    r = request_func(
                                url,
                                timeout=DEFAULT_TIMEOUT,
                                **kwargs)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            message = 'Error connecting to server. {0}'.format(error_message)
            self.error_print(message)
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress('Connecting to endpoint')
        # make rest call
        ret_val, _ = self._make_rest_call('/users', action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            self.save_progress(TEST_CONNECTIVITY_FAILED)
            return action_result.get_status()

        self.save_progress('Test Connectivity Passed')
        self.save_progress('Connected to Zoom API successfully')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_user_settings(self, param):

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param['user_id']

        ret_val, response = self._make_rest_call('/users/{}/settings'.format(user_id), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, 'User settings for id {} successfully retrieved'.format(user_id))

    def _handle_update_user_settings(self, param):
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param['user_id']

        pmi_password = self._get_password(param.get('pmi_password'), param.get('gen_pmi_password'))
        waiting_room = param.get('waiting_room')
        req_password_sched = param.get('req_password_sched')
        req_password_inst = param.get('req_password_inst')
        req_password_pmi = param.get('req_password_pmi')

        is_waiting_room_updated = waiting_room != 'None'
        is_req_password_sched_updated = req_password_sched != 'None'  # pragma: allowlist secret
        is_req_password_inst = req_password_inst != 'None'  # pragma: allowlist secret
        if not(pmi_password or is_waiting_room_updated or is_req_password_sched_updated or is_req_password_inst):
            return action_result.set_status(phantom.APP_ERROR, 'No settings were selected for update')

        data = {}

        if pmi_password or req_password_sched != 'None' or req_password_inst != 'None' or req_password_pmi != 'None':  # pragma: allowlist secret
            data['schedule_meeting'] = {}
            if pmi_password:
                data['schedule_meeting']['pmi_password'] = pmi_password
            if req_password_sched:
                is_req_pass_true = req_password_sched == 'True'  # pragma: allowlist secret
                data['schedule_meeting']['require_password_for_scheduling_new_meetings'] = is_req_pass_true
            if req_password_inst:
                is_req_pass_inst_true = req_password_inst == 'True'  # pragma: allowlist secret
                data['schedule_meeting']['require_password_for_instant_meetings'] = is_req_pass_inst_true
            if req_password_pmi:
                req_pass_pmi = 'all' if req_password_pmi == 'True' else 'none'  # pragma: allowlist secret
                data['schedule_meeting']['require_password_for_pmi_meetings'] = req_pass_pmi
        if waiting_room != 'None':
            data['in_meeting'] = {'waiting_room': waiting_room == 'True'}

        ret_val, _ = self._make_rest_call('/users/{}/settings'.format(user_id), action_result, json=data, headers=None, method='patch')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({
            'pmi_password': ('Not Updated' if not(pmi_password) else pmi_password),
            'waiting_room': ('Not Updated' if waiting_room == 'None' else waiting_room),
            'require_password_for_instant_meetings': ('Not Updated' if req_password_inst == 'None'  # pragma: allowlist secret
                                                      else req_password_inst),
            'require_password_for_scheduling_new_meetings': ('Not Updated' if req_password_sched == 'None'  # pragma: allowlist secret
                                                             else req_password_sched),
            'require_password_for_personal_meeting_instance': ('Not Updated' if req_password_pmi == 'None'  # pragma: allowlist secret
                                                               else req_password_pmi)
        })

        return action_result.set_status(phantom.APP_SUCCESS, 'User {} successfully updated'.format(user_id))

    def _handle_delete_meeting(self, param):
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        meeting_id = param['meeting_id']

        ret_val, _ = self._make_rest_call('/meetings/{}'.format(meeting_id), action_result, headers=None, method='delete')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({
            'meeting_deleted': True,
        })

        return action_result.set_status(phantom.APP_SUCCESS, 'Meeting {} successfully deleted'.format(meeting_id))

    def _get_password(self, password, pass_gen):
        if pass_gen:
            pwgen = PasswordGenerator()
            pwgen.maxlen = 10
            return pwgen.generate()
        else:
            return password

    def _handle_create_meeting(self, param):
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param['user_id']
        password = self._get_password(param.get('password'), param.get('gen_password'))
        waiting_room = param.get('waiting_room')
        topic = param.get('topic')
        agenda = param.get('agenda')

        data = {}

        input_param_dict = {
            'password': password,
            'topic': topic,
            'agenda': agenda,
        }

        for key, value in input_param_dict.items():
            if value:
                data[key] = value

        if waiting_room != 'None':
            data['settings'] = {'waiting_room': (waiting_room == 'True')}

        ret_val, res = self._make_rest_call('/users/{}/meetings'.format(user_id), action_result, json=data, headers=None, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(res)

        action_result.update_summary({
            'meeting_id': str(res['id']),
            'meeting_created': True,
            'password': password if password else 'Not Added',
            'waiting_room': ('Not Added' if waiting_room == 'None' else waiting_room)
        })

        return action_result.set_status(phantom.APP_SUCCESS, 'Meeting {} successfully created'.format(res['id']))

    def _handle_update_meeting(self, param):
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        meeting_id = param['meeting_id']
        password = self._get_password(param.get('password'), param.get('gen_password'))
        waiting_room = param.get('waiting_room')

        if not(password or waiting_room != 'None'):
            return action_result.set_status(phantom.APP_ERROR, 'Either password or waiting room must be updated')

        data = {}

        if password:
            data['password'] = password
        if waiting_room != 'None':
            data['settings'] = {'waiting_room': (waiting_room == 'True')}

        ret_val, _ = self._make_rest_call('/meetings/{}'.format(meeting_id), action_result, json=data, headers=None, method='patch')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({
            'meeting_updated': True,
            'password': password,
            'waiting_room': ('Not Updated' if waiting_room == 'None' else waiting_room)
        })

        return action_result.set_status(phantom.APP_SUCCESS, 'Meeting {} successfully updated'.format(meeting_id))

    def _handle_get_meeting_invitation(self, param):
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        meeting_id = param['meeting_id']

        ret_val, response = self._make_rest_call('/meetings/{}/invitation'.format(meeting_id), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        parsed_fields = {}

        try:
            for kv_pair in UnicodeDammit(response.get('invitation', '')).unicode_markup.replace('Join Zoom Meeting\r\n',
                                                                                                'invitation_link:').split('\r\n'):
                if kv_pair:
                    parts = kv_pair.split(':')
                    second_part = ':'.join(parts[1:]).strip()
                    if second_part:
                        parsed_fields[parts[0].lower().replace(' ', '_')] = second_part

            if parsed_fields.get('meeting_id'):
                parsed_fields['meeting_id'] = parsed_fields['meeting_id'].replace(' ', '')

        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.debug_print('Error: {}'.format(error_message))
            self.save_progress('Could not parse invitation fields')

        response['parsed_fields'] = parsed_fields

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, 'Meeting invitation for id {} successfully retrieved'.format(meeting_id))

    def _handle_get_user(self, param):

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param['user_id']

        ret_val, response = self._make_rest_call('/users/{}'.format(user_id), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, 'User information for id {} successfully retrieved'.format(user_id))

    def _handle_get_meeting(self, param):

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        meeting_id = param['meeting_id']

        ret_val, response = self._make_rest_call('/meetings/{}'.format(meeting_id), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, 'Meeting information for id {} successfully retrieved'.format(meeting_id))

    def _get_token(self, config):
        params = {
            "grant_type": "account_credentials",
            "account_id": self._account_id
        }
        try:
            response = requests.post(GET_TOKEN_URL, params=params, auth=HTTPBasicAuth(self._client_id, self._client_secret))  # nosemgrep
        except Exception:
            self.debug_print("Error in connecting to the server")
            self._token = None
            return
        self._token = json.loads(response.text).get("access_token")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        if action_id == TEST_CONNECTIVITY_IDENTIFIER:
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_user':
            ret_val = self._handle_get_user(param)

        elif action_id == 'create_meeting':
            ret_val = self._handle_create_meeting(param)

        elif action_id == 'get_meeting':
            ret_val = self._handle_get_meeting(param)

        elif action_id == 'get_meeting_invitation':
            ret_val = self._handle_get_meeting_invitation(param)

        elif action_id == 'update_meeting':
            ret_val = self._handle_update_meeting(param)

        elif action_id == 'delete_meeting':
            ret_val = self._handle_delete_meeting(param)

        elif action_id == 'get_user_settings':
            ret_val = self._handle_get_user_settings(param)

        elif action_id == 'update_user_settings':
            ret_val = self._handle_update_user_settings(param)

        return ret_val

    def initialize(self):

        # Load the state
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}

        # Get the asset config
        config = self.get_config()
        self._client_id = config.get("client_id")
        self._client_secret = config.get("client_secret")
        self._token = self._state.get("token")
        self._base_url = config['base_url'].rstrip('/')
        self._auth_method = config['auth_method']
        self._api_key = config.get("api_key")
        self._api_secret = config.get("api_secret")
        self._account_id = config.get("account_id")

        if self._auth_method == SERVER_TO_SERVER_OAUTH_METHOD:
            if not self._client_id or not self._client_secret or not self._account_id:
                action_result = self.add_action_result(ActionResult(dict()))
                message = "client id or client secret or account id not found."
                if self.get_action_identifier() != TEST_CONNECTIVITY_IDENTIFIER:
                    message += " Please re-run test connectivity first."
                else:
                    self.save_progress(TEST_CONNECTIVITY_FAILED)
                return action_result.set_status(
                    phantom.APP_ERROR, message
                )

            if self._token:
                try:
                    self._token = encryption_helper.decrypt(self._token, self.get_asset_id())
                except Exception:
                    self._token = None
                    self.save_progress("error in decrypting token")
            if self.get_action_identifier() == TEST_CONNECTIVITY_IDENTIFIER or not self._token:
                self._get_token(config)
        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self._state["token"] = self._token
        if self._auth_method == SERVER_TO_SERVER_OAUTH_METHOD and self._token:
            try:
                self._state["token"] = encryption_helper.encrypt(self._token, self.get_asset_id())
            except Exception:
                return phantom.APP_ERROR
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass('Password: ')

    if (username and password):
        try:
            login_url = ZoomConnector._get_phantom_base_url() + '/login'

            print('Accessing the Login page')
            r = requests.get(login_url, timeout=DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print('Logging into Platform to get the session id')
            r2 = requests.post(login_url, timeout=DEFAULT_TIMEOUT, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print('Unable to get session id from the platform. Error: ' + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ZoomConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
