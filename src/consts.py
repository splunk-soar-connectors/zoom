# Copyright (c) 2021-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Zoom API constants."""

DEFAULT_TIMEOUT = 30.0
GET_TOKEN_URL = "https://zoom.us/oauth/token"
INVALID_TOKEN_CODES = {124}
INVALID_TOKEN_MESSAGES = {"Invalid access token.", "Access token is expired."}
TEST_CONNECTIVITY_SUCCESS = "Test Connectivity Passed"
TEST_CONNECTIVITY_FAILED = "Test connectivity failed"
