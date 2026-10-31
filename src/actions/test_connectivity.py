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

"""Test Connectivity action."""

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params
from ..app import Asset, app
from ..helper import ZoomHelper
from ..consts import TEST_CONNECTIVITY_FAILED, TEST_CONNECTIVITY_SUCCESS
from ..output_models import TestConnectivityOutput

logger = getLogger()

class TestConnectivityParams(Params):
    pass

class TestConnectivityOutput(ActionOutput):
    pass

@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    logger.progress("Connecting to endpoint")
    helper = ZoomHelper(asset)
    try:
        helper.make_rest_call("/users", force_renew=True)
    except ActionFailure as exc:
        soar.set_message(f"{TEST_CONNECTIVITY_FAILED}: {exc}")
        raise ActionFailure(f"{TEST_CONNECTIVITY_FAILED}: {exc}") from exc
    soar.set_message(f"{TEST_CONNECTIVITY_SUCCESS}\nConnected to Zoom API successfully")
