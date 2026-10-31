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

"""Get User action."""

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params
from ..app import Asset, app
from ..helper import ZoomHelper
from ..output_models import GetUserOutput

logger = getLogger()

class GetUserParams(Params):
    user_id: str = Param(description='Zoom user ID', required=True, primary=True, cef_types=['zoom user id'], column_name="User ID")

@app.action(description="Get zoom user info", action_type="investigate", read_only=True, render_as="table")
def get_user(params: GetUserParams, soar: SOARClient, asset: Asset) -> GetUserOutput:
    logger.progress("Getting Zoom user information")
    user_id = params.user_id
    user_id_path = ZoomHelper.encode_path_segment(user_id, "user_id")
    response = ZoomHelper(asset).make_rest_call(f"/users/{user_id_path}")
    soar.set_message(f"User information for id {user_id} successfully retrieved")
    return GetUserOutput(**response)
