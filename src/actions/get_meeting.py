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

"""Get Meeting action."""

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params
from ..app import Asset, app
from ..helper import ZoomHelper
from ..output_models import GetMeetingOutput

logger = getLogger()

class GetMeetingParams(Params):
    meeting_id: str = Param(description='Zoom meeting ID', required=True, primary=True, cef_types=['zoom meeting id'], column_name="Meeting ID")

@app.action(description="Get zoom meeting details", action_type="investigate", read_only=True, render_as="table")
def get_meeting(params: GetMeetingParams, soar: SOARClient, asset: Asset) -> GetMeetingOutput:
    logger.progress("Getting Zoom meeting details")
    meeting_id = params.meeting_id
    meeting_id_path = ZoomHelper.encode_path_segment(meeting_id, "meeting_id")
    response = ZoomHelper(asset).make_rest_call(f"/meetings/{meeting_id_path}")
    safe_response = ZoomHelper.without_meeting_credentials(response)
    soar.set_message(f"Meeting information for id {meeting_id} successfully retrieved")
    return GetMeetingOutput(action_status="success", **safe_response)
